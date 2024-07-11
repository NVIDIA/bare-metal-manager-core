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

use crate::machine_a_tron::MachineATronInstance;
use crate::redfish::MachineATronBackedRedfishClientPool;
use crate::utils::IntegrationTestEnvironment;
use ::machine_a_tron::config::{MachineATronConfig, MachineConfig};
use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::{self, PathBuf},
    sync::Arc,
    time::{self, Duration},
};

use grpcurl::grpcurl;
use host::machine_validation_completed;
use sqlx::{Postgres, Row};
use tokio::time::sleep;

mod api_server;
mod dpu;
pub mod grpcurl;
mod host;
mod instance;
mod machine;
mod machine_a_tron;
mod metrics;
mod redfish;
mod subnet;
mod upgrade;
mod utils;
mod vault;
mod vpc;

/// Integration test that shells out to start the real carbide-api, and then does all the steps
/// that `bootstrap-forge-docker` would do.
/// It requires `grpcurl` and `vault` on the PATH,
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial_test::serial] // These tests drop/create a postgres database, prevent them from running concurrently
async fn test_integration() -> eyre::Result<()> {
    let Some(test_env) = IntegrationTestEnvironment::try_from_environment().await? else {
        return Ok(());
    };

    // Save typing...
    let IntegrationTestEnvironment {
        carbide_api_addr,
        root_dir,
        carbide_metrics_addr,
        db_pool,
        db_url: _,
        telemetry_setup: _,
    } = test_env.clone();

    // Run bmc-mock
    let mut routers = HashMap::default();
    routers.insert(
        "".to_owned(),
        bmc_mock::default_router(bmc_mock::BmcState { use_qemu: false }),
    );
    tokio::spawn(bmc_mock::run_combined_mock::<String>(routers, None, None));

    let server_handle = utils::start_api_server(test_env, None).await?;

    // And now.. Behold! The Test!

    // Before the initial host bootstrap, the dns_records view
    // should contain 0 entries.
    assert_eq!(0i64, get_dns_record_count(&db_pool).await);

    let agent_config_file = tempfile::NamedTempFile::new()?;
    let upgrade_indicator_file = tempfile::NamedTempFile::new()?;
    let dpu_info = dpu::bootstrap(
        agent_config_file.path(),
        upgrade_indicator_file.path(),
        carbide_api_addr,
        &root_dir,
    )
    .await?;
    let host_machine_id = host_boostrap(carbide_api_addr).await?;

    // After the host_bootstrap, the dns_records view
    // should contain 6 entries:
    // - 2x "human friendly" for Host + DPU.
    // - 2x Machine ID (BMC) for Host + DPU.
    // - 2x Machine ID (ADM) for HOst + DPU.
    assert_eq!(6i64, get_dns_record_count(&db_pool).await);

    // Metrics are only updated after the machine state controller run one more
    // time since the emitted metrics are for states at the start of the iteration.
    // Therefore wait for the updated metrics to show up.
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="ready",substate=""} 1"#,
    )
    .await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);
    metrics::assert_not_metric_line(
        &metrics,
        "machine_reboot_attempts_in_booting_with_discovery_image",
    );

    upgrade::upgrade_dpu(
        upgrade_indicator_file.path(),
        carbide_api_addr,
        db_pool.clone(),
        &dpu_info.machine_id,
    )
    .await?;
    // An upgraded dpu-agent exits so that systemd can start the new version. Be systemd.
    tokio::spawn(agent::start(agent::Options {
        version: false,
        config_path: Some(agent_config_file.path().to_path_buf()),
        cmd: Some(agent::AgentCommand::Run(agent::RunOptions {
            enable_metadata_service: false,
            override_machine_id: Some(dpu_info.machine_id.clone()),
            override_network_virtualization_type: None,
            skip_upgrade_check: false,
        })),
    }));
    tokio::time::sleep(Duration::from_secs(1)).await;
    upgrade::confirm_upgraded(db_pool.clone(), &dpu_info.machine_id).await?;

    let vpc_id = vpc::create(carbide_api_addr)?;
    let segment_id = subnet::create(carbide_api_addr, &vpc_id)?;

    // Create instance with phone_home enabled
    let instance_id = instance::create(carbide_api_addr, &host_machine_id, &segment_id, true)?;
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="assigned",substate="ready"} 1"#,
    )
    .await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_machines_per_state{fresh="true",state="ready",substate=""}"#,
    );
    metrics::assert_not_metric_line(
        &metrics,
        "machine_reboot_attempts_in_booting_with_discovery_image",
    );

    instance::release(carbide_api_addr, &host_machine_id, &instance_id)?;

    let metrics = metrics::wait_for_metric_line(carbide_metrics_addr, r#"forge_machines_per_state{fresh="true",state="waitingforcleanup",substate="hostcleanup"} 1"#).await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);

    machine::cleanup_completed(carbide_api_addr, &host_machine_id)?;

    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Host/MachineValidating")?;

    machine::machine_validation_completed(carbide_api_addr, &host_machine_id)?;

    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Discovered")?;

    // It stays in Discovered until we notify that reboot happened, which this test doesn't
    let metrics = metrics::wait_for_metric_line(
        carbide_metrics_addr,
        r#"forge_machines_per_state{fresh="true",state="hostnotready",substate="discovered"} 1"#,
    )
    .await?;
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_machines_per_state{fresh="true",state="assigned""#,
    );

    // Explicitly test that the histogram for `forge_reboot_attempts_in_booting_with_discovery_image_bucket`
    // uses the custom buckets we defined for retries/attempts
    for &(bucket, count) in &[(0, 0), (1, 1), (2, 1), (3, 1), (5, 1), (10, 1)] {
        metrics::assert_metric_line(
            &metrics,
            &format!(
                r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{{le="{bucket}"}} {count}"#
            ),
        );
    }
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="4"}"#,
    );
    metrics::assert_not_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="6"}"#,
    );
    metrics::assert_metric_line(
        &metrics,
        r#"forge_reboot_attempts_in_booting_with_discovery_image_bucket{le="+Inf"} 1"#,
    );
    metrics::assert_metric_line(
        &metrics,
        "forge_reboot_attempts_in_booting_with_discovery_image_sum 1",
    );
    metrics::assert_metric_line(
        &metrics,
        "forge_reboot_attempts_in_booting_with_discovery_image_count 1",
    );

    sleep(time::Duration::from_millis(500)).await;
    fs::remove_dir_all(dpu_info.hbn_root)?;
    server_handle.stop().await?;
    db_pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial_test::serial] // These tests drop/create a postgres database, prevent them from running concurrently
async fn test_integration_machine_a_tron() -> eyre::Result<()> {
    let Some(test_env) = IntegrationTestEnvironment::try_from_environment().await? else {
        return Ok(());
    };

    let carbide_api_addr = test_env.carbide_api_addr;
    let root_dir = test_env.root_dir.clone();

    let mat_config = MachineATronConfig {
        machines: BTreeMap::from([(
            "config".to_string(),
            MachineConfig {
                host_count: 1,
                dpu_per_host_count: 1,
                boot_delay: 1,
                dpu_reboot_delay: 1,
                host_reboot_delay: 1,
                template_dir: root_dir
                    .join("dev/machine-a-tron/templates")
                    .to_str()
                    .unwrap()
                    .to_string(),
                admin_dhcp_relay_address: Ipv4Addr::new(172, 20, 0, 2),
                oob_dhcp_relay_address: Ipv4Addr::new(172, 20, 0, 2),
                vpc_count: 0,
            },
        )]),
        carbide_api_url: Some(format!(
            "https://{}:{}",
            carbide_api_addr.ip(),
            carbide_api_addr.port()
        )),
        log_file: None,
        bmc_mock_host_tar: format!(
            "{}/dev/bmc-mock/lenovo_thinksystem_sr670.tar.gz",
            root_dir.to_string_lossy()
        ),
        bmc_mock_dpu_tar: format!(
            "{}/dev/bmc-mock/nvidia_dpu.tar.gz",
            root_dir.to_string_lossy()
        ),
        use_pxe_api: true,
        pxe_server_host: None,
        pxe_server_port: None,
        bmc_mock_dynamic_ports: true,
        bmc_mock_port: 0, // unused, we're using dynamic ports on localhost
        dhcp_server_address: None,
        interface: String::from("UNUSED"), // unused, we're using dynamic ports on localhost
        tui_enabled: false,
        sudo_command: None,
        use_dhcp_api: true,
    };

    // Note: We need to start the API server before running machine-a-tron, or it will fail to
    // initialize. This means we need to construct an empty mock redfish pool first, then start the
    // API server with it, then start machine-a-tron, *then* we can add the machines to the pool.
    let mock_redfish_pool = Arc::new(MachineATronBackedRedfishClientPool::new());
    let server_handle =
        utils::start_api_server(test_env.clone(), Some(mock_redfish_pool.clone())).await?;

    let tenant1_vpc = vpc::create(carbide_api_addr)?;
    subnet::create(carbide_api_addr, &tenant1_vpc)?;

    let MachineATronInstance {
        join_handle,
        host_machines,
    } = machine_a_tron::run_local(mat_config, root_dir)
        .await
        .unwrap();

    // Now that machine-a-tron is started, we can add its machines to mock_redfish_pool
    mock_redfish_pool
        .host_machines
        .lock()
        .await
        .extend_from_slice(&host_machines);

    let timeout = Duration::from_secs(20 * 60);
    tokio::select! {
        _ = sleep(timeout) => {
            panic!("Timed out after {} seconds waiting for machines to achieve ready status", timeout.as_secs());
        }
        msg = join_handle => msg?,
    }?;
    server_handle.stop().await?;
    test_env.db_pool.close().await;
    Ok(())
}

/// Bootstraps a Host in `ready` state. Returns the `machine_id`
async fn host_boostrap(carbide_api_addr: SocketAddr) -> eyre::Result<String> {
    let host_machine_id = host::bootstrap(carbide_api_addr)?;

    // Wait until carbide-api is prepared to admit the DPU might have rebooted.
    // There are hard coded sleeps in carbide-api before this happens.
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "WaitForDPUUp")?;

    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Host/MachineValidating")?;

    machine_validation_completed(carbide_api_addr, &host_machine_id)?;

    // After DPU reboot forge_dpu_agent reports health to carbide-api, triggering state transition
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Host/Discovered")?;

    grpcurl(
        carbide_api_addr,
        "ForgeAgentControl",
        Some(
            &serde_json::json!({
                "machine_id": {"id": host_machine_id}
            })
            .to_string(),
        ),
    )?;
    grpcurl(
        carbide_api_addr,
        "RebootCompleted",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "Ready")?;
    tracing::info!("ManagedHost is up in Ready state.");
    Ok(host_machine_id)
}

fn find_prerequisites() -> eyre::Result<HashMap<String, PathBuf>> {
    let mut bins = HashMap::with_capacity(2);
    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    bins.insert("vault", find_first_in("vault", &paths));
    bins.insert("grpcurl", find_first_in("grpcurl", &paths));
    bins.insert("curl", find_first_in("curl", &paths));

    let mut full_paths = HashMap::with_capacity(bins.len());
    for (k, v) in bins.drain() {
        match v {
            Some(full_path) => {
                full_paths.insert(k.to_string(), full_path);
            }
            None => {
                eyre::bail!("Missing prerequisite binary: {k}");
            }
        }
    }

    Ok(full_paths)
}

// Look for a binary in the given paths, return full path or None if not found
fn find_first_in(binary: &str, paths: &[path::PathBuf]) -> Option<path::PathBuf> {
    for path in paths {
        let candidate = path.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// Get the current number of rows in the dns_records view,
// which is expected to start at 0, and then progress, as
// the test continues.
//
// TODO(chet): Find a common place for this and the same exact
// function in api/tests/dns.rs to exist, instead of it being
// in two places.
pub async fn get_dns_record_count(pool: &sqlx::Pool<Postgres>) -> i64 {
    let mut txn = pool.begin().await.unwrap();
    let query = "SELECT COUNT(*) as row_cnt FROM dns_records";
    let rows = sqlx::query::<_>(query).fetch_one(&mut *txn).await.unwrap();
    rows.try_get("row_cnt").unwrap()
}
