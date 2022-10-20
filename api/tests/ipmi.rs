/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use log::LevelFilter;
use sqlx::PgPool;
use tokio::time;
use uuid::Uuid;

use carbide::bg::{Status, TaskState};
use carbide::db::ipmi::{BmcMetaData, BmcMetaDataRequest, BmcMetadataItem, UserRoles};
use carbide::ipmi::{ipmi_handler, IpmiCommand, IpmiCommandHandler, IpmiTask};
use carbide::vault::CredentialProvider;
use carbide::CarbideResult;

use crate::vault::TestCredentialProvider;

mod vault;

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

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_ipmi_cred(pool: PgPool) {
    let mut txn = pool.begin().await.unwrap();

    let machine_id: Uuid = "52dfecb4-8070-4f4b-ba95-f66d0f51fd98".parse().unwrap();

    let credentials_provider = TestCredentialProvider::new();
    BmcMetaData {
        machine_id,
        ip: "127.0.0.2".to_string(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0,
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),
    }
    .update_bmc_meta_data(&mut txn, &credentials_provider)
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataRequest {
            machine_id,
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
    ) -> CarbideResult<String> {
        match cmd.action.unwrap() {
            IpmiTask::PowerControl(_task) => Ok("Power Control".to_string()),
            IpmiTask::Status => Ok("Status".to_string()),
        }
    }
}

#[sqlx::test]
async fn test_ipmi(pool: PgPool) {
    let credential_provider = Arc::new(TestCredentialProvider::new());
    let _handle = ipmi_handler(pool.clone(), TestIpmiCommandHandler {}, credential_provider).await;
    let job = IpmiCommand::new(
        "127.0.0.1".to_string(),
        "deadbeef-dead-beef-dead-beefdeadbeef"
            .to_string()
            .parse()
            .unwrap(),
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
