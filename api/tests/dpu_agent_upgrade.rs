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

use std::time::SystemTime;

use ::rpc::forge as rpc;
use ::rpc::forge::forge_server::Forge;
use carbide::model::machine::machine_id;

mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_upgrade_check(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        machine_id::try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await)
            .unwrap();

    // Set the upgrade policy
    let response = env
        .api
        .dpu_agent_upgrade_policy_action(tonic::Request::new(rpc::DpuAgentUpgradePolicyRequest {
            new_policy: Some(rpc::AgentUpgradePolicy::UpOnly as i32),
        }))
        .await?
        .into_inner();
    assert_eq!(
        response.active_policy,
        rpc::AgentUpgradePolicy::UpOnly as i32,
        "Policy should be what we set"
    );
    assert!(response.did_change, "Policy should have changed");

    // We'll need to know the current network config version in order to register our
    // forge-dpu-agent version
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(
            rpc::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            },
        ))
        .await?
        .into_inner();

    // Report that we're on an old version of the DPU
    // That should trigger marking us for upgrade
    let hs = rpc::NetworkHealth {
        is_healthy: true,
        passed: vec!["ContainerExists".to_string(), "checkTwo".to_string()],
        failed: vec!["".to_string()],
        message: None,
    };
    let network_config_version = response.managed_host_config_version.clone();
    env.api
        .record_dpu_network_status(tonic::Request::new(rpc::DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            // BEGIN This is the important line for this test
            dpu_agent_version: Some("v2023.06-rc2-1-gc5c05de3".to_string()),
            // END
            observed_at: None,
            health: Some(hs),
            dpu_health: Some(::rpc::health::HealthReport {
                source: "forge-dpu-agent".to_string(),
                observed_at: None,
                successes: vec![],
                alerts: vec![],
            }),
            network_config_version: Some(network_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec!["1.2.3.4".to_string()],
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
        }))
        .await
        .unwrap();

    // Check if we need to upgrade - answer should be yes
    let response = env
        .api
        .dpu_agent_upgrade_check(tonic::Request::new(rpc::DpuAgentUpgradeCheckRequest {
            machine_id: dpu_machine_id.to_string(),
            current_agent_version: "v2023.06-rc2-1-gc5c05de3".to_string(),
            binary_mtime: Some(SystemTime::now().into()),
            binary_sha: "f86df8a4c022a8e64b5655b0063b3e18107891aefd766df8f34a6e53fda3fde9"
                .to_string(),
        }))
        .await?;
    let resp = response.into_inner();
    assert!(
        resp.should_upgrade,
        "DPU reported old version so should be asked to upgrade"
    );
    let current_version = forge_version::v!(build_version);
    assert_eq!(
        resp.package_version,
        current_version[1..],
        "Debian package version is our version minus initial 'v'"
    );

    Ok(())
}
