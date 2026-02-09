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
use std::time::SystemTime;

use ::rpc::forge as rpc;
use ::rpc::forge::forge_server::Forge;
use chrono::{Duration, Utc};
use common::api_fixtures::create_test_env;
use health_report::{HealthAlertClassification, HealthProbeAlert, HealthProbeId};

use crate::tests::common;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, TestManagedHost, create_managed_host, create_test_env_with_overrides,
};

#[crate::sqlx_test]
async fn test_upgrade_check(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    let dpu_machine_id = create_managed_host(&env).await.dpu().id;

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
                dpu_machine_id: dpu_machine_id.into(),
            },
        ))
        .await?
        .into_inner();

    // Report that we're on an old version of the DPU
    // That should trigger marking us for upgrade
    let network_config_version = response.managed_host_config_version.clone();
    env.api
        .record_dpu_network_status(tonic::Request::new(rpc::DpuNetworkStatus {
            dpu_machine_id: dpu_machine_id.into(),
            // BEGIN This is the important line for this test
            dpu_agent_version: Some("v2023.06-rc2-1-gc5c05de3".to_string()),
            // END
            observed_at: None,
            dpu_health: Some(::rpc::health::HealthReport {
                source: "forge-dpu-agent".to_string(),
                observed_at: None,
                successes: vec![],
                alerts: vec![],
            }),
            network_config_version: Some(network_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec!["1.2.3.4".to_string()],
                prefixes: vec!["1.2.3.4/32".to_string()],
                gateways: vec!["1.2.3.1".to_string()],
                network_security_group: None,
                internal_uuid: None,
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            fabric_interfaces: vec![],
            last_dhcp_requests: vec![],
            dpu_extension_service_version: Some("V1-T1".to_string()),
            dpu_extension_services: vec![],
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
    let current_version = carbide_version::v!(build_version);
    assert_eq!(
        resp.package_version,
        current_version[1..],
        "Debian package version is our version minus initial 'v'"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_dpu_agent_version_staleness(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Set up a 1 day staleness threshold
    let env = create_test_env_with_overrides(
        db_pool.clone(),
        TestEnvOverrides {
            dpu_agent_version_staleness_threshold: Some(Duration::days(1)),
            prevent_allocations_on_stale_dpu_agent_version: Some(true),
            ..Default::default()
        },
    )
    .await;

    let stale_version = "stale_version";
    let recently_superseded_version = "recently_superseded_version";
    let current_version = carbide_version::v!(build_version);
    let stale_time = Utc::now() - Duration::hours(25);
    let recently_superseded_time = Utc::now() - Duration::hours(23);

    {
        let mut txn = env.pool.begin().await?;
        db::carbide_version::make_mock_observation(&mut txn, stale_version, Some(stale_time))
            .await?;
        db::carbide_version::make_mock_observation(
            &mut txn,
            recently_superseded_version,
            Some(recently_superseded_time),
        )
        .await?;
        db::carbide_version::make_mock_observation(&mut txn, current_version, None).await?;
        txn.commit().await?;
    }

    let mh = create_managed_host(&env).await;

    // We'll need to know the current network config version in order to register our
    // forge-dpu-agent version
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(
            rpc::ManagedHostNetworkConfigRequest {
                dpu_machine_id: mh.dpu().id.into(),
            },
        ))
        .await?
        .into_inner();

    // Report that we're on a stale version of the dpu agent
    let alert = mh
        .mock_observation_and_get_only_health_alert(
            &env,
            Some(stale_version),
            &response.managed_host_config_version,
        )
        .await
        .expect("Should have caused a health alert");
    assert_eq!(
        alert.message,
        format!(
            "Agent version is {stale_version}, which is out of date since {}",
            stale_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )
    );
    assert_eq!(alert.target, Some(mh.dpu().id.to_string()));
    assert_eq!(
        alert.classifications,
        vec![HealthAlertClassification::prevent_allocations()]
    );
    assert_eq!(alert.id, HealthProbeId::stale_agent_version());

    // Now try with the superseded-but-not-yet-stale version
    assert!(
        mh.mock_observation_and_get_only_health_alert(
            &env,
            Some(recently_superseded_version),
            &response.managed_host_config_version
        )
        .await
        .is_none()
    );

    // Now try with no build number
    let alert = mh
        .mock_observation_and_get_only_health_alert(
            &env,
            None,
            &response.managed_host_config_version,
        )
        .await
        .expect("Should have caused a health alert");
    assert_eq!(alert.message, "Agent version is not known");
    assert_eq!(alert.target, Some(mh.dpu().id.to_string()),);
    assert_eq!(
        alert.classifications,
        vec![HealthAlertClassification::prevent_allocations()]
    );
    assert_eq!(alert.id, HealthProbeId::stale_agent_version());

    // Finally, a matching version should be fine
    assert!(
        mh.mock_observation_and_get_only_health_alert(
            &env,
            Some(current_version),
            &response.managed_host_config_version
        )
        .await
        .is_none()
    );

    Ok(())
}

impl TestManagedHost {
    async fn mock_observation_and_get_only_health_alert(
        &self,
        test_env: &TestEnv,
        agent_version: Option<&str>,
        managed_host_config_version: &str,
    ) -> Option<HealthProbeAlert> {
        test_env
            .api
            .record_dpu_network_status(tonic::Request::new(rpc::DpuNetworkStatus {
                dpu_machine_id: self.dpu().id.into(),
                dpu_agent_version: agent_version.map(Into::into),
                observed_at: None,
                dpu_health: Some(::rpc::health::HealthReport {
                    source: "forge-dpu-agent".to_string(),
                    observed_at: None,
                    successes: vec![],
                    alerts: vec![],
                }),
                network_config_version: Some(managed_host_config_version.to_string()),
                instance_id: None,
                instance_config_version: None,
                instance_network_config_version: None,
                interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                    function_type: rpc::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    mac_address: None,
                    addresses: vec!["1.2.3.4".to_string()],
                    prefixes: vec!["1.2.3.4/32".to_string()],
                    gateways: vec!["1.2.3.1".to_string()],
                    network_security_group: None,
                    internal_uuid: None,
                }],
                network_config_error: None,
                client_certificate_expiry_unix_epoch_secs: None,
                fabric_interfaces: vec![],
                last_dhcp_requests: vec![],
                dpu_extension_service_version: Some("V1-T1".to_string()),
                dpu_extension_services: vec![],
            }))
            .await
            .unwrap();

        test_env.run_machine_state_controller_iteration().await;

        let alerts = test_env
            .api
            .find_machines_by_ids(tonic::Request::new(rpc::MachinesByIdsRequest {
                machine_ids: vec![self.id],
                include_history: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .machines
            .into_iter()
            .next()
            .expect("expected host machine to be found")
            .health
            .expect("expected health report")
            .alerts;

        if alerts.is_empty() {
            None
        } else {
            assert_eq!(
                alerts.len(),
                1,
                "Expected a single alert, got {}",
                alerts.len()
            );
            Some(alerts.into_iter().next().unwrap().try_into().unwrap())
        }
    }
}
