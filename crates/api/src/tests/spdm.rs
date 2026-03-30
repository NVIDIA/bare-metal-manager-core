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

        // now check the attestation history table
        let mut txn = env.pool.begin().await.unwrap();
        let devices_history =
            sqlx::query("SELECT * FROM spdm_device_attestation_history WHERE machine_id=$1")
                .bind(machine_id)
                .fetch_all(&mut *txn)
                .await?;
        txn.commit().await.unwrap();

        assert_eq!(devices_history.len(), 13);

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

        // now let's just move to the failed state
        for _ in 0..8 {
            env.run_spdm_controller_iteration_no_requeue().await;
        }

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
}
