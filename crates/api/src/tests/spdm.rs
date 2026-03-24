/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pub mod tests {

    use carbide_uuid::machine::MachineId;
    use model::attestation::spdm::{SpdmAttestationState, SpdmObjectId};
    use rpc::forge::forge_server::Forge;
    use sqlx::PgConnection;
    //use sqlx::PgConnection;
    use tonic::Request;

    use crate::tests::common::api_fixtures::{
        RedfishOverrides, TestEnvOverrides, create_managed_host, create_test_env,
        create_test_env_with_overrides,
    };

    // A simple test to test basic db functions.
    #[crate::sqlx_test]
    async fn test_attestation_succeeds(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        // trigger attestation - corresponding device attestations are created
        // query attestation status - should be in progress
        // run controller iterations - should be able to:
        // - fetch metadata
        // - fetch certificate,
        // - schedule evidence
        // - poll and collect evidence
        // - do nras verification
        // - apply appraisal policy
        // - move into passed state
        // verify the state in each iteration using direct db lookups

        let env = create_test_env(pool).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let _ = env
            .api
            .trigger_machine_attestation(Request::new(machine_id))
            .await?;

        // device attestations should be created now
        let machine_ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(()))
            .await?
            .into_inner();

        assert_eq!(1, machine_ids.machine_ids.len());

        let machine_id = machine_ids.machine_ids[0];

        // check that attestation's status is InProgress
        let response = env
            .api
            .get_machine_attestation_status(Request::new(machine_id))
            .await?
            .into_inner();

        assert_eq!(
            rpc::forge::SpdmAttestationStatus::SpdmAttInProgress,
            response.attestation_status()
        );

        // now, look at the state of the attestation and check that it is FetchMetadata
        let mut txn = env.pool.begin().await.unwrap();

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");

        for object_id in &object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert_eq!(SpdmAttestationState::FetchMetadata, attestation_state);
        }

        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");
            if device_id == "ERoT_BMC_0" {
                // an unsupported device
                assert_eq!(SpdmAttestationState::Passed, attestation_state);
            } else {
                assert_eq!(SpdmAttestationState::FetchCertificate, attestation_state);
            }
        }

        // now proceed to FetchCertificate
        env.run_spdm_controller_iteration_no_requeue().await;

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");
        // ERoT_BMC_0 is in Passed state now, so should not be included anymore
        assert_eq!(2, object_ids.len());

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(
                    attestation_state,
                    SpdmAttestationState::TriggerEvidenceCollection { .. }
                ),
                "expected TriggerEvidenceCollection, got: {:?}",
                attestation_state
            );
        }

        // now move onto PollEvidenceCollection
        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(
                    attestation_state,
                    SpdmAttestationState::PollEvidenceCollection { .. }
                ),
                "expected PollEvidenceCollection, got: {:?}",
                attestation_state
            );
        }

        // after we collected the evidence, do the NRAS verification
        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(attestation_state, SpdmAttestationState::NrasVerification),
                "expected NrasVerification, got: {:?}",
                attestation_state
            );
        }

        // do the policy appraisal
        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(
                    attestation_state,
                    SpdmAttestationState::ApplyAppraisalPolicy
                ),
                "expected ApplyAppraisalPolicy, got: {:?}",
                attestation_state
            );
        }

        // and finally we should be in the Passed state
        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(attestation_state, SpdmAttestationState::Passed),
                "expected Passed, got: {:?}",
                attestation_state
            );
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_component_integrity_fails_no_attestation_started(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        // set up redfish to return no component integrities
        let overrides = TestEnvOverrides {
            redfish_overrides: Some(RedfishOverrides {
                no_component_integrities: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let env = create_test_env_with_overrides(pool, overrides).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let response = env
            .api
            .trigger_machine_attestation(Request::new(machine_id))
            .await?;

        assert_eq!(0, response.into_inner().devices_under_attestation);

        // device attestations should not be created
        let machine_ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(()))
            .await?
            .into_inner();

        assert_eq!(0, machine_ids.machine_ids.len());

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_fetch_metadata_fails_state_does_not_change(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        // set up redfish to return an error in FetchMetadata state
        let overrides = TestEnvOverrides {
            redfish_overrides: Some(RedfishOverrides {
                firmware_for_component_error: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let env = create_test_env_with_overrides(pool, overrides).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let response = env
            .api
            .trigger_machine_attestation(Request::new(machine_id))
            .await?;

        assert_eq!(3, response.into_inner().devices_under_attestation);

        // device attestations should be created
        let machine_ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(()))
            .await?
            .into_inner();

        assert_eq!(1, machine_ids.machine_ids.len());

        // redfish will return an error
        let mut txn = env.pool.begin().await.unwrap();

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");

        for _ in 0..5 {
            env.run_spdm_controller_iteration_no_requeue().await;
        }

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(attestation_state, SpdmAttestationState::FetchMetadata),
                "expected FetchMetadata, got: {:?}",
                attestation_state
            );
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_poll_evidence_fails_controller_retries_then_fails(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        // set up redfish to return an error in FetchMetadata state
        let overrides = TestEnvOverrides {
            redfish_overrides: Some(RedfishOverrides {
                get_task_trigger_evidence_returns_interrupted: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let env = create_test_env_with_overrides(pool, overrides).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let response = env
            .api
            .trigger_machine_attestation(Request::new(machine_id))
            .await?;

        assert_eq!(3, response.into_inner().devices_under_attestation);

        // device attestations should be created
        let machine_ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(()))
            .await?
            .into_inner();

        assert_eq!(1, machine_ids.machine_ids.len());

        let mut txn = env.pool.begin().await.unwrap();

        // let's loop until we are triggering evidence and verify that
        for _ in 0..8 {
            env.run_spdm_controller_iteration_no_requeue().await;
        }

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(
                    attestation_state,
                    SpdmAttestationState::TriggerEvidenceCollection { retry_count: 3 }
                ),
                "expected Trigger, got: {:?}",
                attestation_state
            );
        }

        // now let's just fast forward to the failed state
        env.run_spdm_controller_iteration().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(attestation_state, SpdmAttestationState::Failed { .. }),
                "expected Failed, got: {:?}",
                attestation_state
            );
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_cancelled_by_user_goes_into_cancelled(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        // trigger attestation - corresponding device attestations are created
        // query attestation status - should be in progress
        // run controller iterations - should be able to:
        // - fetch metadata
        // - fetch certificate,
        // - schedule evidence
        // -  cancel the whole thing - make sure it goes into cancelled state
        // verify the state in each iteration using direct db lookups

        let env = create_test_env(pool).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let _ = env
            .api
            .trigger_machine_attestation(Request::new(machine_id))
            .await?;

        // device attestations should be created now
        let machine_ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(()))
            .await?
            .into_inner();

        assert_eq!(1, machine_ids.machine_ids.len());

        let machine_id = machine_ids.machine_ids[0];

        // check that attestation's status is InProgress
        let response = env
            .api
            .get_machine_attestation_status(Request::new(machine_id))
            .await?
            .into_inner();

        assert_eq!(
            rpc::forge::SpdmAttestationStatus::SpdmAttInProgress,
            response.attestation_status()
        );

        // now, look at the state of the attestation and check that it is FetchMetadata
        let mut txn = env.pool.begin().await.unwrap();

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");

        for object_id in &object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert_eq!(SpdmAttestationState::FetchMetadata, attestation_state);
        }

        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");
            if device_id == "ERoT_BMC_0" {
                // an unsupported device
                assert_eq!(SpdmAttestationState::Passed, attestation_state);
            } else {
                assert_eq!(SpdmAttestationState::FetchCertificate, attestation_state);
            }
        }

        // now proceed to FetchCertificate
        env.run_spdm_controller_iteration_no_requeue().await;

        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .expect("Failed getting object ids for attestation");
        // ERoT_BMC_0 is in Passed state now, so should not be included anymore
        assert_eq!(2, object_ids.len());

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(
                    attestation_state,
                    SpdmAttestationState::TriggerEvidenceCollection { .. }
                ),
                "expected TriggerEvidenceCollection, got: {:?}",
                attestation_state
            );
        }

        // now let's cancel the whole thing
        let _ = env
            .api
            .cancel_machine_attestation(Request::new(machine_id))
            .await?;

        env.run_spdm_controller_iteration_no_requeue().await;

        for object_id in &*object_ids {
            let SpdmObjectId(_, device_id) = object_id;
            let attestation_state = get_state_from_db(&mut txn, &machine_id, device_id)
                .await
                .expect("Failed getting attestation state from the DB");

            assert!(
                matches!(attestation_state, SpdmAttestationState::Cancelled),
                "expected Cancelled, got: {:?}",
                attestation_state
            );
        }

        Ok(())
    }

    async fn get_state_from_db(
        txn: &mut PgConnection,
        machine_id: &MachineId,
        device_id: &str,
    ) -> Result<SpdmAttestationState, sqlx::Error> {
        let query = r#"
            SELECT state
            FROM spdm_machine_devices_attestation
            WHERE machine_id = $1 AND device_id = $2
        "#;

        sqlx::query_as(query)
            .bind(machine_id)
            .bind(device_id)
            .fetch_one(txn)
            .await
    }
    /*
    // helper for adding entry into history table.
    pub async fn insert_into_history_table(
        txn: &mut PgConnection,
        machine_id: MachineId,
        count: i32,
    ) -> eyre::Result<()> {
        let query = r#"INSERT INTO spdm_machine_attestation_history (machine_id, state_snapshot)
        VALUES ($1, $2)"#;

        let mut devices_state: HashMap<String, SpdmDeviceAttestationState> = HashMap::new();
        devices_state
            .entry("GPU0".to_string())
            .or_insert(SpdmDeviceAttestationState::CollectData(
                CollectionStep::FetchMetadata,
            ));
        devices_state.entry("GPU1".to_string()).or_insert(
            SpdmDeviceAttestationState::Verification(VerificationStep::VerificationCompleted),
        );

        let history_state = SpdmMachineAttestationState {
            devices_state,
            overall_state:
                model::attestation::spdm::SpdmAttestationState::CheckIfAttestationSupported,
            device_state: Some(SpdmDeviceAttestationState::Verification(
                VerificationStep::VerificationCompleted,
            )),
            machine_version: ConfigVersion::initial(),
            device_version: Some(ConfigVersion::initial().increment()),
            update_machine_version: true,
            update_device_version: false,
        };
        for _ in 0..count {
            sqlx::query(query)
                .bind(machine_id)
                .bind(sqlx::types::Json(&history_state))
                .execute(&mut *txn)
                .await?;
        }

        Ok(())
    }

    // Test history db insert
    // This will be updated once we know how to trim the table, trigger or cron.
    #[crate::sqlx_test]
    async fn test_history_db_insert(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool).await;
        let (machine_id, dpu_id) = create_managed_host(&env).await.into();
        let mut txn = env.pool.begin().await.unwrap();
        insert_into_history_table(&mut txn, machine_id, 10).await?;
        insert_into_history_table(&mut txn, dpu_id, 10).await?;
        txn.commit().await.unwrap();

        let mut txn = env.pool.begin().await.unwrap();
        let host: Vec<SpdmMachineAttestationHistory> =
            sqlx::query_as("SELECT * FROM spdm_machine_attestation_history WHERE machine_id=$1")
                .bind(machine_id)
                .fetch_all(&mut *txn)
                .await?;

        let dpu: Vec<SpdmMachineAttestationHistory> =
            sqlx::query_as("SELECT * FROM spdm_machine_attestation_history WHERE machine_id=$1")
                .bind(dpu_id)
                .fetch_all(&mut *txn)
                .await?;
        txn.commit().await.unwrap();

        assert_eq!(host.len(), 10);
        assert_eq!(dpu.len(), 10);

        Ok(())
    }

    // Success case
    #[crate::sqlx_test]
    async fn test_trigger_host_attestation(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        // this will insert an entry into spdm_machine_attestation table
        let _res = env
            .api
            .trigger_machine_attestation(Request::new(AttestationData {
                machine_id: Some(machine_id),
            }))
            .await?;

        // check that the values had been inserted
        let _ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(AttestationIdsRequest {}))
            .await?
            .into_inner()
            .machine_ids;
        assert_eq!(_ids.len(), 1);
        assert_eq!(_ids[0], machine_id);

        // this is the same method as used by StateControllerIO's list_objects
        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        println!("KB: ch1: object ids are {:?}", object_ids);

        // since we haven't moved past the scheduling state, we should have
        // just one machine only attestation
        assert_eq!(object_ids.len(), 1);
        assert_eq!(object_ids[0].0, machine_id);

        // this iteration will check if machine supports attestation
        env.run_spdm_controller_iteration().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::ScheduleAttestation)
        );
        env.run_spdm_controller_iteration().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::PerformAttestation)
        );

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert_eq!(object_ids.len(), 3);

        // Drive all attestation state machines to completion first
        for i in 0..20 {
            env.run_spdm_controller_iteration().await;
            if test_device_states(
                &[
                    "AttestationCompleted { status: NotSupported }",
                    "AttestationCompleted { status: Success }",
                    "AttestationCompleted { status: Success }",
                ],
                &machine_id,
                &env,
            )
            .await
            {
                break;
            }
            if i == 19 {
                panic!("Attestation state machines did not complete in expected iterations");
            }
        }

        let _machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();

        assert_eq!(_machine.machines[0].state, "Completed");
        assert_eq!(_machine.machines[0].status, "Completed");

        let history_by_device: HashMap<String, Vec<String>> =
            device_state_histories(&env, &machine_id).await;
        assert_eq!(
            history_by_device,
            HashMap::from_iter([
                ("ERoT_BMC_0".to_string(), vec!["AttestationCompleted { status: NotSupported }".to_string()]),
                ("HGX_IRoT_GPU_0".to_string(), vec!["FetchData(FetchCertificate)".to_string(), "FetchData(Trigger { retry_count: 0 })".to_string(), "FetchData(Poll { task_id: \"0\", retry_count: 0 })".to_string(), "FetchData(Collect)".to_string(), "FetchData(Collected)".to_string(), "Verification(GetVerifierResponse)".to_string(), "Verification(VerifyResponse { state: RawAttestationOutcome { overall_outcome: (\"JWT\", \"All_good\"), devices_outcome: {} } })".to_string(), "Verification(VerificationCompleted)".to_string(), "ApplyEvidenceResultAppraisalPolicy(ApplyAppraisalPolicy)".to_string(), "ApplyEvidenceResultAppraisalPolicy(AppraisalPolicyValidationCompleted)".to_string(), "AttestationCompleted { status: Success }".to_string()]),
                ("HGX_IRoT_GPU_1".to_string(), vec!["FetchData(FetchCertificate)".to_string(), "FetchData(Trigger { retry_count: 0 })".to_string(), "FetchData(Poll { task_id: \"0\", retry_count: 0 })".to_string(), "FetchData(Collect)".to_string(), "FetchData(Collected)".to_string(), "Verification(GetVerifierResponse)".to_string(), "Verification(VerifyResponse { state: RawAttestationOutcome { overall_outcome: (\"JWT\", \"All_good\"), devices_outcome: {} } })".to_string(), "Verification(VerificationCompleted)".to_string(), "ApplyEvidenceResultAppraisalPolicy(ApplyAppraisalPolicy)".to_string(), "ApplyEvidenceResultAppraisalPolicy(AppraisalPolicyValidationCompleted)".to_string(), "AttestationCompleted { status: Success }".to_string()])
            ])
        );

        Ok(())
    }

    /// Returns the device state histories for the given machine
    async fn device_state_histories(
        env: &TestEnv,
        machine_id: &MachineId,
    ) -> HashMap<String, Vec<String>> {
        let mut txn = env.pool.begin().await.unwrap();
        let history: Vec<SpdmMachineAttestationHistory> = sqlx::query_as(
            "SELECT * FROM spdm_machine_attestation_history WHERE machine_id=$1 ORDER BY ID ASC",
        )
        .bind(machine_id)
        .fetch_all(&mut *txn)
        .await
        .unwrap();
        let history: Vec<SpdmMachineAttestationState> = history
            .into_iter()
            .map(|entry| entry.state_snapshot)
            .collect();

        let mut history_by_device: HashMap<String, Vec<String>> = HashMap::new();
        for history in &history {
            for (device_id, device_state) in &history.devices_state {
                let device_state = format!("{:?}", device_state);
                let device_history = history_by_device.entry(device_id.to_string()).or_default();

                if device_history
                    .last()
                    .is_none_or(|last_state| *last_state != device_state)
                {
                    device_history.push(device_state.clone());
                }
            }
        }
        txn.commit().await.unwrap();
        history_by_device
    }

    async fn test_device_states(states: &[&str], machine_id: &MachineId, env: &TestEnv) -> bool {
        let mut success = true;
        let ids = ["ERoT_BMC_0", "HGX_IRoT_GPU_0", "HGX_IRoT_GPU_1"];
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![*machine_id],
            }))
            .await
            .unwrap()
            .into_inner();

        for (id, state) in ids.iter().zip(states.iter()) {
            let device = machine.machines[0]
                .device_data
                .iter()
                .find(|x| x.device_id == *id)
                .unwrap();

            success &= device.state == *state;
        }

        success
    }

    async fn validate_device_states(states: &[&str], machine_id: &MachineId, env: &TestEnv) {
        let ids = ["ERoT_BMC_0", "HGX_IRoT_GPU_0", "HGX_IRoT_GPU_1"];
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![*machine_id],
            }))
            .await
            .unwrap()
            .into_inner();

        for (id, state) in ids.iter().zip(states.iter()) {
            let device = machine.machines[0]
                .device_data
                .iter()
                .find(|x| x.device_id == *id)
                .unwrap();

            assert_eq!(state.to_string(), device.state,);
        }
    }

    // Cancel case
    #[crate::sqlx_test]
    async fn test_trigger_host_attestation_cancel(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let _res = env
            .api
            .trigger_machine_attestation(Request::new(AttestationData {
                machine_id: Some(machine_id),
            }))
            .await?;

        let _ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(AttestationIdsRequest {}))
            .await?
            .into_inner()
            .machine_ids;
        assert_eq!(_ids.len(), 1);
        assert_eq!(_ids[0], machine_id);

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        assert_eq!(object_ids.len(), 1);

        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::ScheduleAttestation)
        );
        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::PerformAttestation)
        );

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert_eq!(object_ids.len(), 3);

        validate_device_states(
            &[
                "FetchData(FetchMetadata)",
                "FetchData(FetchMetadata)",
                "FetchData(FetchMetadata)",
            ],
            &machine_id,
            &env,
        )
        .await;

        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(FetchCertificate)",
                "FetchData(FetchCertificate)",
            ],
            &machine_id,
            &env,
        )
        .await;

        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(Trigger { retry_count: 0 })",
                "FetchData(Trigger { retry_count: 0 })",
            ],
            &machine_id,
            &env,
        )
        .await;
        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(Poll { task_id: \"0\", retry_count: 0 })",
                "FetchData(Poll { task_id: \"0\", retry_count: 0 })",
            ],
            &machine_id,
            &env,
        )
        .await;

        let mut txn = env.pool.begin().await.unwrap();
        db::attestation::spdm::cancel_machine_attestation(&mut txn, &machine_id)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert_eq!(object_ids.len(), 0);
        Ok(())
    }

    // Restart case
    #[crate::sqlx_test]
    async fn test_trigger_host_attestation_restart(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let _res = env
            .api
            .trigger_machine_attestation(Request::new(AttestationData {
                machine_id: Some(machine_id),
            }))
            .await?;

        let _ids = env
            .api
            .find_machine_ids_under_attestation(Request::new(AttestationIdsRequest {}))
            .await?
            .into_inner()
            .machine_ids;
        assert_eq!(_ids.len(), 1);
        assert_eq!(_ids[0], machine_id);

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        assert_eq!(object_ids.len(), 1);

        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::ScheduleAttestation)
        );
        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .list_attestations_for_machine_ids(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", SpdmAttestationState::PerformAttestation)
        );

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert_eq!(object_ids.len(), 3);

        validate_device_states(
            &[
                "FetchData(FetchMetadata)",
                "FetchData(FetchMetadata)",
                "FetchData(FetchMetadata)",
            ],
            &machine_id,
            &env,
        )
        .await;

        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(FetchCertificate)",
                "FetchData(FetchCertificate)",
            ],
            &machine_id,
            &env,
        )
        .await;

        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(Trigger { retry_count: 0 })",
                "FetchData(Trigger { retry_count: 0 })",
            ],
            &machine_id,
            &env,
        )
        .await;
        env.run_spdm_controller_iteration_no_requeue().await;
        validate_device_states(
            &[
                "AttestationCompleted { status: NotSupported }",
                "FetchData(Poll { task_id: \"0\", retry_count: 0 })",
                "FetchData(Poll { task_id: \"0\", retry_count: 0 })",
            ],
            &machine_id,
            &env,
        )
        .await;

        // Restart the attestation
        let _res = env
            .api
            .trigger_machine_attestation(Request::new(AttestationData {
                machine_id: Some(machine_id),
            }))
            .await?;

        let mut txn = env.pool.begin().await.unwrap();
        let object_ids = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        // Devices must not be counted now.
        assert_eq!(object_ids.len(), 1);
        Ok(())
    }
    */
}
