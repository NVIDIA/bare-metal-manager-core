/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::sync::Arc;

use async_trait::async_trait;
use carbide::model::machine::machine_id::try_parse_machine_id;
use log::LevelFilter;
use sqlx::PgPool;
use tokio::time;

use carbide::bg::{Status, TaskState};
use carbide::db::ipmi::{
    BmcMetaDataGetRequest, BmcMetaDataUpdateRequest, BmcMetadataItem, UserRoles,
};
use carbide::ipmi::{ipmi_handler, IpmiCommand, IpmiCommandHandler, IpmiTask};
use carbide::CarbideResult;
use forge_credentials::CredentialProvider;
pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine, FIXTURE_X86_MACHINE_ID};
use common::test_credentials::TestCredentialProvider;

const DATA: [(UserRoles, &str, &str); 3] = [
    (UserRoles::Administrator, "forge_admin", "randompassword"),
    (UserRoles::User, "forge_user", "randompassword"),
    (UserRoles::Operator, "forge_operator", "randompassword"),
];

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Debug)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn machine_bmc_credential_update(pool: PgPool) {
    let env = create_test_env(pool.clone(), Default::default());
    // TODO: This probably should test with a host machine instead of a DPU,
    // since for DPUs we don't really store BMC credentials
    let dpu_rpc_machine_id = create_dpu_machine(&env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = pool.begin().await.unwrap();

    let credentials_provider = TestCredentialProvider::new();
    BmcMetaDataUpdateRequest {
        machine_id: dpu_machine_id.clone(),
        ip: "127.0.0.2".to_string(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0,
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),
        mac: "01:02:03:04:05:06".to_string(),
    }
    .update_bmc_meta_data(&mut txn, &credentials_provider)
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataGetRequest {
            machine_id: dpu_machine_id.clone(),
            role: d.0,
        };

        let response = ipmi_req
            .get_bmc_meta_data(&mut txn, &credentials_provider)
            .await
            .unwrap();
        assert_eq!(response.ip, "127.0.0.2".to_string());
        assert_eq!(response.user, d.1.to_string());
        assert_eq!(response.password, d.2.to_string());
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TestIpmiCommandHandler {}

#[async_trait]
impl IpmiCommandHandler for TestIpmiCommandHandler {
    async fn handle_ipmi_command(
        &self,
        cmd: IpmiCommand,
        _credential_provider: Arc<dyn CredentialProvider>,
        _pool: sqlx::PgPool,
    ) -> CarbideResult<String> {
        match cmd.action.unwrap() {
            IpmiTask::PowerControl(_task) => Ok("Power Control".to_string()),
            IpmiTask::Status => Ok("Status".to_string()),
            IpmiTask::EnableLockdown => Ok("Enable Lockdown".to_string()),
            IpmiTask::DisableLockdown => Ok("Disable Lockdown".to_string()),
            IpmiTask::LockdownStatus => Ok("Lockdown Status".to_string()),
            IpmiTask::SetupSerialConsole => Ok("Setup Serial Console".to_string()),
            IpmiTask::SerialConsoleStatus => Ok("Serial Console Status Status".to_string()),
            IpmiTask::FirstBootDevice(_device, _once) => Ok("First Boot Device".to_string()),
        }
    }
}

#[sqlx::test]
async fn test_ipmi(pool: PgPool) {
    let credential_provider = Arc::new(TestCredentialProvider::new());
    let _handle = ipmi_handler(pool.clone(), TestIpmiCommandHandler {}, credential_provider).await;
    let job = IpmiCommand::new(
        "127.0.0.1".to_string(),
        FIXTURE_X86_MACHINE_ID.parse().unwrap(),
        UserRoles::Administrator,
    );

    let job_id = job.power_up(&pool).await.unwrap();

    loop {
        if Status::is_finished(&pool, job_id).await.unwrap() {
            break;
        }
        time::sleep(time::Duration::from_millis(1000)).await;
    }

    let fs = Status::poll(&pool, job_id).await.unwrap();
    assert_eq!(fs.state, TaskState::Finished);
    assert_eq!(fs.msg.trim(), "Power Control");
}
