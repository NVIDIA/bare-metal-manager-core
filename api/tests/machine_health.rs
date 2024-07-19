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

mod common;
use std::time::SystemTime;

use carbide::db;
use common::api_fixtures::{create_managed_host, create_test_env, dpu};
use rpc::forge::forge_server::Forge;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_health_reporting(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    // After a Machine had been created, it should report healthy
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    let host_health = host_machine.health.clone().unwrap();
    assert!(host_health.alerts.is_empty());
    assert!(host_health.successes.is_empty());
    let dpu_machine = env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);
    let dpu_health = dpu_machine.health.clone().unwrap();
    assert_eq!(dpu_health.source, "forge-dpu-agent".to_string());
    assert!(dpu_health.alerts.is_empty());

    // TODO: Check this via API in the future
    let mut txn = env.pool.begin().await?;
    let aggregate_health = db::managed_host::load_snapshot(&mut txn, &host_machine_id)
        .await?
        .unwrap()
        .aggregate_health;
    txn.rollback().await?;
    assert_eq!(aggregate_health.source, "aggregate-host-health");
    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(aggregate_health.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
    assert!(aggregate_health.alerts.is_empty());

    // Let forge-dpu-agent submit a report which claims the DPU is no longer healthy
    let dpu_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // Tell API about latest network config and machine health
    // We use just the new format of health-reports, which should take precendence
    // over the legacy format
    let network_health = rpc::forge::NetworkHealth {
        is_healthy: true,
        passed: vec![],
        failed: vec![],
        message: None,
    };
    let dpu_health = health_report::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![health_report::HealthProbeSuccess {
            id: "Success1".parse().unwrap(),
        }],
        alerts: vec![health_report::HealthProbeAlert {
            id: "Failure1".parse().unwrap(),
            in_alert_since: None,
            message: "Failure1".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        }],
    };
    env.api
        .record_dpu_network_status(tonic::Request::new(rpc::forge::DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: Some(dpu_health.clone().into()),
            health: Some(network_health),
            network_config_version: Some(dpu_network_config.managed_host_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                mac_address: None,
                addresses: vec![dpu_network_config
                    .admin_interface
                    .as_ref()
                    .unwrap()
                    .ip
                    .clone()],
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
        }))
        .await
        .unwrap();

    // The host health shouldn't have changed yet. It's updated in the next
    // state controller iteration
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    let host_health = host_machine.health.clone().unwrap();
    assert!(host_health.alerts.is_empty());
    assert!(host_health.successes.is_empty());
    // DPU health already indicates the issue
    let dpu_machine = env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);
    let reported_dpu_health = dpu_machine.health.clone().unwrap();
    assert_eq!(reported_dpu_health.source, "forge-dpu-agent".to_string());
    let mut expected_dpu_health = dpu_health.clone();
    expected_dpu_health.source = "forge-dpu-agent".to_string();
    assert!(health_reports_equal(
        &expected_dpu_health.clone().into(),
        &reported_dpu_health
    ));
    // Aggregate health in snapshot also indicates the issue
    // TODO: Check this via API in the future
    let mut txn = env.pool.begin().await?;
    let aggregate_health = db::managed_host::load_snapshot(&mut txn, &host_machine_id)
        .await?
        .unwrap()
        .aggregate_health;
    txn.rollback().await?;
    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(aggregate_health.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
    let mut expected_host_health_report = expected_dpu_health.clone();
    expected_host_health_report.source = "aggregate-host-health".to_string();
    assert!(health_reports_equal(
        &expected_host_health_report.into(),
        &aggregate_health.into()
    ));

    Ok(())
}

/// Returns whether 2 healthreports are equal, without taking timestamps into consideration
fn health_reports_equal(a: &rpc::health::HealthReport, b: &rpc::health::HealthReport) -> bool {
    fn erase_timestamps(report: &mut rpc::health::HealthReport) {
        report.observed_at = None;
        for alert in report.alerts.iter_mut() {
            alert.in_alert_since = None;
        }
    }

    let mut a = a.clone();
    let mut b = b.clone();
    erase_timestamps(&mut a);
    erase_timestamps(&mut b);
    a == b
}
