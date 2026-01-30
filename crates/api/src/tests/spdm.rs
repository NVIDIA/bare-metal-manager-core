/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub mod tests {
    use std::collections::HashMap;

    use carbide_uuid::machine::MachineId;
    use config_version::ConfigVersion;
    use db::attestation::spdm::insert_devices;
    use model::attestation::spdm::{
        AttestationDeviceState, AttestationState, FetchDataDeviceStates,
        SpdmMachineAttestationHistory, SpdmMachineStateSnapshot, VerificationDeviceStates,
    };
    use rpc::forge::forge_server::Forge;
    use rpc::forge::{AttestationData, AttestationIdsRequest, AttestationMachineList};
    use sqlx::PgConnection;
    use tonic::Request;

    use crate::tests::common::api_fixtures::{TestEnv, create_managed_host, create_test_env};

    // A simple test to test basic db functions.
    #[crate::sqlx_test]
    async fn test_trigger_host_attestation_db(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
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
        let data = db::attestation::spdm::find_machine_ids_for_attestation(&mut txn).await?;
        assert_eq!(data.len(), 1);
        txn.commit().await.unwrap();

        env.run_spdm_controller_iteration().await;

        let mut txn = env.pool.begin().await.unwrap();
        insert_devices(
            &mut txn,
            &machine_id,
            vec![model::attestation::spdm::SpdmMachineDeviceAttestation {
                machine_id,
                device_id: "HGX_IRoT_GPU_0".to_string(),
                nonce: uuid::Uuid::new_v4(),
                state: model::attestation::spdm::AttestationDeviceState::FetchData(
                    FetchDataDeviceStates::FetchMetadata,
                ),
                state_version: ConfigVersion::initial(),
                state_outcome: None,
                metadata: None,
                ca_certificate_link: None,
                ca_certificate: None,
                evidence_target: None,
                evidence: None,
            }],
        )
        .await?;

        txn.commit().await.unwrap();

        let mut machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        let att_data = machine.machines.remove(0);
        assert_eq!(att_data.machine_id.unwrap(), machine_id);
        assert_eq!(att_data.device_data.len(), 1);

        let _res = env
            .api
            .cancel_machine_attestation(Request::new(AttestationData {
                machine_id: Some(machine_id),
            }))
            .await?;

        let mut machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();

        let att_data = machine.machines.remove(0);
        assert_eq!(att_data.machine_id.unwrap(), machine_id);
        assert!(att_data.requested_at.unwrap() < att_data.canceled_at.unwrap());

        Ok(())
    }

    // helper for adding entry into history table.
    pub async fn insert_into_history_table(
        txn: &mut PgConnection,
        machine_id: MachineId,
        count: i32,
    ) -> eyre::Result<()> {
        let query = r#"INSERT INTO spdm_machine_attestation_history (machine_id, state_snapshot)
        VALUES ($1, $2)"#;

        let mut devices_state: HashMap<String, AttestationDeviceState> = HashMap::new();
        devices_state
            .entry("GPU0".to_string())
            .or_insert(AttestationDeviceState::FetchData(
                FetchDataDeviceStates::FetchMetadata,
            ));
        devices_state
            .entry("GPU1".to_string())
            .or_insert(AttestationDeviceState::Verification(
                VerificationDeviceStates::VerificationCompleted,
            ));

        let history_state = SpdmMachineStateSnapshot {
            devices_state,
            machine_state: model::attestation::spdm::AttestationState::CheckIfAttestationSupported,
            device_state: Some(AttestationDeviceState::Verification(
                VerificationDeviceStates::VerificationCompleted,
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

        env.run_spdm_controller_iteration().await;
        let machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!(
                "{:#?}",
                AttestationState::FetchAttestationTargetsAndUpdateDb
            )
        );
        env.run_spdm_controller_iteration().await;
        let machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", AttestationState::FetchData)
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
            .find_machines_under_attestation(Request::new(AttestationMachineList {
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
        let history: Vec<SpdmMachineStateSnapshot> = history
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
            .find_machines_under_attestation(Request::new(AttestationMachineList {
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
            .find_machines_under_attestation(Request::new(AttestationMachineList {
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
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!(
                "{:#?}",
                AttestationState::FetchAttestationTargetsAndUpdateDb
            )
        );
        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", AttestationState::FetchData)
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
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!(
                "{:#?}",
                AttestationState::FetchAttestationTargetsAndUpdateDb
            )
        );
        env.run_spdm_controller_iteration_no_requeue().await;
        let machine = env
            .api
            .find_machines_under_attestation(Request::new(AttestationMachineList {
                machine_ids: vec![machine_id],
            }))
            .await?
            .into_inner();
        assert_eq!(
            machine.machines[0].state,
            format!("{:#?}", AttestationState::FetchData)
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
}
