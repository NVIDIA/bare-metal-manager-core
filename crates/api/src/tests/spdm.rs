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

    use db::attestation::spdm::insert_device;
    use forge_uuid::machine::MachineId;
    use model::attestation::spdm::{
        AttestationDeviceState, FetchMeasurementDeviceStates, SpdmAttestationStatus,
        SpdmMachineAttestationHistory, SpdmMachineHistoryState, VerificationDeviceStates,
    };
    use rpc::forge::forge_server::Forge;
    use rpc::forge::{AttestationData, AttestationIdsRequest, AttestationMachineList};
    use sqlx::PgConnection;
    use tonic::Request;

    use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

    // A simple test to test basic db functions.
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
        let data = db::attestation::spdm::load_snapshots_for_attestation(&mut txn).await?;
        assert_eq!(data.len(), 1);
        txn.commit().await.unwrap();

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
        assert!(att_data.device_data.is_empty());
        assert!(att_data.requested_at.unwrap() < att_data.canceled_at.unwrap());

        let mut txn = env.pool.begin().await.unwrap();
        insert_device(
            &mut txn,
            &model::attestation::spdm::SpdmMachineDeviceAttestation {
                machine_id,
                device_id: "HGX_IRoT_GPU_0".to_string(),
                nonce: uuid::Uuid::new_v4(),
                state: model::attestation::spdm::AttestationDeviceState::FetchMesurements(
                    FetchMeasurementDeviceStates::FetchMetadata,
                ),
                last_known_metadata: None,
                current_metadata: None,
                ca_certificate_link: None,
                ca_certificate: None,
                evidence_target: None,
                evidence: None,
            },
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

        Ok(())
    }

    // helper for adding entry into history table.
    pub async fn insert_into_history_table(
        txn: &mut PgConnection,
        machine_id: MachineId,
        count: i32,
    ) -> eyre::Result<()> {
        let query = r#"INSERT INTO spdm_machine_attestation_history (machine_id, state_snapshot, state_version, attestation_status)
        VALUES ($1, $2, $3, $4)"#;

        let mut devices_state: HashMap<String, AttestationDeviceState> = HashMap::new();
        devices_state.entry("GPU0".to_string()).or_insert(
            AttestationDeviceState::FetchMesurements(FetchMeasurementDeviceStates::FetchMetadata),
        );
        devices_state
            .entry("GPU1".to_string())
            .or_insert(AttestationDeviceState::Verification(
                VerificationDeviceStates::VerificationCompleted,
            ));

        let history_state = SpdmMachineHistoryState {
            state: model::attestation::spdm::AttestationState::CheckIfAttestationSupported,
            devices_state,
        };
        for idx in 0..count {
            let version = format!("V{idx}-T{idx}");
            sqlx::query(query)
                .bind(machine_id)
                .bind(sqlx::types::Json(&history_state))
                .bind(version)
                .bind(SpdmAttestationStatus::Started)
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
}
