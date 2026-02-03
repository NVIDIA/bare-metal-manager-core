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
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{self, Duration};

use ::machine_a_tron::{BmcMockRegistry, HostMachineHandle, MachineATronConfig, MachineConfig};
use ::utils::HostPortPair;
use api_test_helper::{
    IntegrationTestEnvironment, domain, instance, machine, metrics, subnet, utils, vpc,
};
use bmc_mock::ListenerOrAddress;
use eyre::ContextCompat;
use futures::FutureExt;
use futures::future::join_all;
use itertools::Itertools;
use sqlx::{Postgres, Row};
use tokio::time::sleep;

#[ctor::ctor]
fn setup() {
    api_test_helper::setup_logging()
}

/// Run multiple machine-a-tron integration tests in parallel against a shared carbide API instance.
#[tokio::test(flavor = "multi_thread")]
async fn test_integration() -> eyre::Result<()> {
    // NOTE: These tests run two carbide-api servers, and the clients are configured to randomly
    // switch between them on every API call. This helps prevent issues that arise when multiple API
    // severs may be running in production.
    let Some(test_env) =
        IntegrationTestEnvironment::try_from_environment(2, "api_server_test_integration").await?
    else {
        return Ok(());
    };

    let carbide_api_addrs = &test_env.carbide_api_addrs;

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = PathBuf::from(format!("{}/crates/bmc-mock", test_env.root_dir.display()));
    let mut bmc_mock_handle = bmc_mock::run_combined_mock(
        bmc_address_registry.clone(),
        Some(certs_dir),
        Some(ListenerOrAddress::Listener(
            // let OS choose available port
            TcpListener::bind("127.0.0.1:0")?,
        )),
    )?;

    // For preingestion firmware checks to work, carbide needs a directory which exists to be
    // configured as the firmware_directory. It can be empty, because our mocks should be showing
    // the desired firmware verisions to carbide (and thus it won't try to update.) This folder will
    // be deleted on Drop.
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;

    // Begin the integration test by starting an API server. This will be shared between multiple
    // individual machine-a-tron-based tests, which can run in parallel against the same instance.
    let (server_handle_1, server_handle_2) = (
        utils::start_api_server(
            test_env.clone(),
            Some(HostPortPair::HostAndPort(
                "127.0.0.1".to_string(),
                bmc_mock_handle.address.port(),
            )),
            empty_firmware_dir.path().to_owned(),
            0,
            true,
        )
        .await?,
        utils::start_api_server(
            test_env.clone(),
            Some(HostPortPair::HostAndPort(
                "127.0.0.1".to_string(),
                bmc_mock_handle.address.port(),
            )),
            empty_firmware_dir.path().to_owned(),
            1,
            true,
        )
        .await?,
    );

    let tenant1_vpc = vpc::create(carbide_api_addrs).await?;
    let domain_id = domain::create(carbide_api_addrs, "tenant-1.local").await?;
    let managed_segment_id =
        subnet::create(carbide_api_addrs, &tenant1_vpc, &domain_id, 10, false).await?;
    subnet::create(carbide_api_addrs, &tenant1_vpc, &domain_id, 11, true).await?;

    // Run several tests in parallel.
    let all_tests = join_all([
        test_machine_a_tron_multidpu(
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_zerodpu(
            &test_env,
            &bmc_address_registry,
            // Relay IP in host-inband net
            Ipv4Addr::new(10, 10, 11, 2),
        )
        .boxed(),
        test_machine_a_tron_singledpu_nic_mode(
            &test_env,
            &bmc_address_registry,
            // Relay IP in host-inband  net
            Ipv4Addr::new(10, 10, 11, 2),
        )
        .boxed(),
    ]);

    tokio::select! {
        results = all_tests => results.into_iter().try_collect()?,
        _ = tokio::time::sleep(Duration::from_secs(20 * 60)) => {
            panic!("Tests did not complete after 20 minutes")
        }
    }

    generate_core_metric_docs(&test_env.carbide_metrics_addrs);

    server_handle_1.stop().await?;
    server_handle_2.stop().await?;
    test_env.db_pool.close().await;
    bmc_mock_handle.stop().await?;
    Ok(())
}

fn generate_core_metric_docs(metrics_endpoints: &[SocketAddr]) {
    let infos = metrics::collect_metric_infos(metrics_endpoints).unwrap();
    // Delete everything with "alt_metric_" prefix
    let infos: Vec<_> = infos
        .into_iter()
        .filter(|metric| !metric.name.starts_with("alt_metric"))
        .collect();
    let mut docs = "# Carbide core metrics\n\n".to_string();
    use std::fmt::Write;

    use askama_escape::Escaper;

    writeln!(
        &mut docs,
        "This file contains a list of metrics exported by Carbide. \
        The list is auto-generated from an integration test (`test_integration`). \
        Metrics for workflows which are not exercised by the test are missing."
    )
    .unwrap();
    writeln!(&mut docs).unwrap();
    writeln!(&mut docs, "<table>").unwrap();
    writeln!(
        &mut docs,
        "<tr><td>Name</td><td>Type</td><td>Description</td></tr>"
    )
    .unwrap();

    for info in &infos {
        write!(&mut docs, "<tr>").unwrap();
        write!(&mut docs, "<td>{}</td>", info.name).unwrap();
        write!(&mut docs, "<td>{}</td>", info.ty).unwrap();
        write!(&mut docs, "<td>").unwrap();
        askama_escape::Html
            .write_escaped(&mut docs, &info.help)
            .unwrap();
        write!(&mut docs, "</td>").unwrap();
        writeln!(&mut docs, "</tr>").unwrap();
    }
    writeln!(&mut docs, "<table>").unwrap();

    let path = std::path::Path::new(METRIC_DOC_PATH);
    assert!(
        path.exists(),
        "Metric path at {} does not exist. Did the directory structure change?",
        path.to_str().unwrap()
    );

    std::fs::write(path, docs).unwrap();
}

pub(crate) const METRIC_DOC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../book/src/manuals/metrics/carbide_core_metrics.md"
);

/// Run integration tests with machine-a-tron, asserting on metrics. This has to run as its own
/// test, to make the values in the metrics buckets predictable.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_metrics_integration() -> eyre::Result<()> {
    let Some(test_env) =
        IntegrationTestEnvironment::try_from_environment(1, "api_server_test_metrics_integration")
            .await?
    else {
        return Ok(());
    };

    // Save typing...
    let IntegrationTestEnvironment {
        carbide_api_addrs,
        root_dir: _,
        carbide_metrics_addrs,
        db_pool,
        metrics: _,
        db_url: _,
        vault_config: _,
        _vault_handle,
    } = test_env.clone();

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = PathBuf::from(format!("{}/crates/bmc-mock", test_env.root_dir.display()));
    let mut bmc_mock_handle = bmc_mock::run_combined_mock(
        bmc_address_registry.clone(),
        Some(certs_dir),
        Some(ListenerOrAddress::Listener(
            // let OS choose available port
            TcpListener::bind("127.0.0.1:0")?,
        )),
    )?;

    // For preingestion firmware checks to work, carbide needs a directory which exists to be
    // configured as the firmware_directory. It can be empty, because our mocks should be showing
    // the desired firmware verisions to carbide (and thus it won't try to update.) This folder will
    // be deleted on Drop.
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;

    // Begin the integration test by starting an API server. This will be shared between multiple
    // individual machine-a-tron-based tests, which can run in parallel against the same instance.
    let server_handle = utils::start_api_server(
        test_env.clone(),
        Some(HostPortPair::HostAndPort(
            "127.0.0.1".to_string(),
            bmc_mock_handle.address.port(),
        )),
        empty_firmware_dir.path().to_owned(),
        0,
        true,
    )
    .await?;

    // Before the initial host bootstrap, the dns_records view
    // should contain 0 entries.
    assert_eq!(0i64, get_dns_record_count(&db_pool).await);

    run_machine_a_tron_test(
        1,
        1,
        false,
        &test_env,
        &bmc_address_registry,
        Ipv4Addr::new(172, 20, 0, 1),
        |machine_handle| {
            let db_pool = db_pool.clone();
            let carbide_api_addrs = carbide_api_addrs.to_vec();
            let carbide_metrics_addrs = carbide_metrics_addrs.to_vec();
            async move {
                machine_handle.dpus()[0].wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90)).await?;

                // After the host_bootstrap, the dns_records view
                // should contain 8 entries:
                // - 2x "human friendly" (BMC) for Host + DPU.
                // - 2x "human friendly" (ADM) for Host + DPU.
                // - 2x Machine ID (BMC) for Host + DPU.
                // - 2x Machine ID (ADM) for Host + DPU.
                assert_eq!(8i64, get_dns_record_count(&db_pool).await);

                // Metrics are only updated after the machine state controller run one more
                // time since the emitted metrics are for states at the start of the iteration.
                // Therefore wait for the updated metrics to show up.
                let metrics = metrics::wait_for_metric_line(
                    &carbide_metrics_addrs,
                    r#"carbide_machines_per_state{fresh="true",state="ready",substate=""} 1"#,
                )
                    .await?;
                metrics::assert_metric_line(&metrics, r#"carbide_machines_total{fresh="true"} 1"#);
                // Also check that metrics are emitted under the configured `alt_metric_prefix`
                metrics::assert_metric_line(&metrics, r#"alt_metric_machines_total{fresh="true"} 1"#);
                metrics::assert_not_metric_line(
                    &metrics,
                    "machine_reboot_attempts_in_booting_with_discovery_image",
                );

                let vpc_id = vpc::create(&carbide_api_addrs).await?;
                let domain_id = domain::create(&carbide_api_addrs, "tenant-1.local").await?;
                let segment_id = subnet::create(&carbide_api_addrs, &vpc_id, &domain_id, 10, false).await?;
                let host_machine_id = machine_handle.observed_machine_id().expect("Should have gotten a machine ID by now");

                // Create instance with phone_home enabled
                let instance_id = instance::create(
                    &carbide_api_addrs,
                    &host_machine_id,
                    Some(&segment_id),
                    Some("test"),
                    true,
                    true,
                    &[],
                ).await?;

                let metrics = metrics::wait_for_metric_line(
                    &carbide_metrics_addrs,
                    r#"carbide_machines_per_state{fresh="true",state="assigned",substate="ready"} 1"#,
                )
                    .await?;
                metrics::assert_metric_line(&metrics, r#"carbide_machines_total{fresh="true"} 1"#);
                metrics::assert_not_metric_line(
                    &metrics,
                    r#"carbide_machines_per_state{fresh="true",state="ready",substate=""}"#,
                );
                metrics::assert_not_metric_line(
                    &metrics,
                    "machine_reboot_attempts_in_booting_with_discovery_image",
                );

                instance::release(&carbide_api_addrs, &host_machine_id, &instance_id, true).await?;

                let metrics = metrics::wait_for_metric_line(&carbide_metrics_addrs, r#"carbide_machines_per_state{fresh="true",state="waitingforcleanup",substate="hostcleanup"} 1"#).await?;
                metrics::assert_metric_line(&metrics, r#"carbide_machines_total{fresh="true"} 1"#);

                machine::wait_for_state(
                    &carbide_api_addrs,
                    &host_machine_id,
                    "MachineValidation",
                ).await?;

                machine::wait_for_state(&carbide_api_addrs, &host_machine_id, "Discovered").await?;

                // It stays in Discovered until we notify that reboot happened, which this test doesn't
                let metrics = metrics::wait_for_metric_line(
                    &carbide_metrics_addrs,
                    r#"carbide_machines_per_state{fresh="true",state="hostnotready",substate="discovered"} 1"#,
                )
                    .await?;
                metrics::assert_not_metric_line(
                    &metrics,
                    r#"carbide_machines_per_state{fresh="true",state="assigned""#,
                );

                // Explicitly test that the histogram for `carbide_reboot_attempts_in_booting_with_discovery_image_bucket`
                // uses the custom buckets we defined for retries/attempts
                for &(bucket, count) in &[(0, 0), (1, 1), (2, 1), (3, 1), (5, 1), (10, 1)] {
                    metrics::assert_metric_line(
                        &metrics,
                        &format!(
                            r#"carbide_reboot_attempts_in_booting_with_discovery_image_bucket{{le="{bucket}"}} {count}"#
                        ),
                    );
                }
                metrics::assert_not_metric_line(
                    &metrics,
                    r#"carbide_reboot_attempts_in_booting_with_discovery_image_bucket{le="4"}"#,
                );
                metrics::assert_not_metric_line(
                    &metrics,
                    r#"carbide_reboot_attempts_in_booting_with_discovery_image_bucket{le="6"}"#,
                );
                metrics::assert_metric_line(
                    &metrics,
                    r#"carbide_reboot_attempts_in_booting_with_discovery_image_bucket{le="+Inf"} 1"#,
                );
                metrics::assert_metric_line(
                    &metrics,
                    "carbide_reboot_attempts_in_booting_with_discovery_image_sum 1",
                );
                metrics::assert_metric_line(
                    &metrics,
                    "carbide_reboot_attempts_in_booting_with_discovery_image_count 1",
                );

                Ok(())
            }
        },
    ).await?;

    sleep(time::Duration::from_millis(500)).await;
    bmc_mock_handle.stop().await?;
    server_handle.stop().await?;
    db_pool.close().await;
    Ok(())
}

async fn test_machine_a_tron_multidpu(
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    segment_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        1,
        2,
        false,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            let segment_id = segment_id.to_string();
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                let instance_id = instance::create(
                    carbide_api_addrs,
                    &machine_id,
                    Some(&segment_id),
                    None,
                    false,
                    false,
                    &[],
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Assigned/Ready", Duration::from_secs(60))
                    .await?;

                let instance_json = instance::get_instance_json_by_machine_id(
                    carbide_api_addrs,
                    machine_handle
                        .observed_machine_id()
                        .expect("HostMachine should have a Machine ID once it's in ready state")
                        .to_string()
                        .as_str(),
                )
                .await?;

                let serde_json::Value::Object(interface) =
                    &instance_json["instances"][0]["status"]["network"]["interfaces"][0]
                else {
                    panic!("Allocated instance does not have interface configuration")
                };

                let serde_json::Value::Array(addrs) = &interface["addresses"] else {
                    panic!("Interface does not have addresses")
                };
                assert_eq!(addrs.len(), 1);

                let serde_json::Value::Array(gateways) = &interface["gateways"] else {
                    panic!("Interface does not have gateways set")
                };
                assert_eq!(gateways.len(), 1);

                tracing::info!(
                    "Machine {machine_id} has made it to Assigned/Ready, releasing instance"
                );
                instance::release(carbide_api_addrs, &machine_id, &instance_id, false).await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(60))
                    .await?;
                tracing::info!("Machine {machine_id} has made it to Ready again, all done");
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_zerodpu(
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        1,
        0,
        false,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready")
                    .to_string();
                tracing::info!("Machine {machine_id} has made it to Ready.");
                // TODO: ZERO DPU's instance handling is not yet clear. Removing this code until
                // carbide starts supporting ZERO DPUs instance creation.
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_singledpu_nic_mode(
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        1,
        1,
        true,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(60))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready")
                    .to_string();
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                // TODO: ZERO DPU/DPU in NIC mode's instance handling is not yet clear. Removing this code until
                // carbide starts supporting ZERO DPUs instance creation.
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn run_machine_a_tron_test<F, O>(
    host_count: u32,
    dpu_per_host_count: u32,
    dpus_in_nic_mode: bool,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    admin_dhcp_relay_address: Ipv4Addr,
    run_assertions: F,
) -> eyre::Result<()>
where
    F: Fn(HostMachineHandle) -> O,
    O: Future<Output = eyre::Result<()>>,
{
    let api_addr = test_env
        .carbide_api_addrs
        .first()
        .copied()
        .context("No carbide API addresses configured")?;
    let additional_api_urls = test_env.carbide_api_addrs[1..]
        .iter()
        .map(|a| format!("https://{}:{}", a.ip(), a.port()))
        .collect();
    let mat_config = MachineATronConfig {
        machines: BTreeMap::from([(
            "config".to_string(),
            Arc::new(MachineConfig {
                host_count,
                dpu_per_host_count,
                boot_delay: 1,
                dpu_reboot_delay: 1,
                host_reboot_delay: 1,
                template_dir: test_env
                    .root_dir
                    .join("crates/machine-a-tron/templates")
                    .to_str()
                    .unwrap()
                    .to_string(),
                admin_dhcp_relay_address,
                oob_dhcp_relay_address: Ipv4Addr::new(172, 20, 1, 1),
                vpc_count: 0,
                subnets_per_vpc: 0,
                run_interval_idle: Duration::from_secs(1),
                run_interval_working: Duration::from_millis(100),
                network_status_run_interval: Duration::from_secs(1),
                scout_run_interval: Duration::from_secs(1),
                dpus_in_nic_mode,
                dpu_firmware_versions: None,
                dpu_agent_version: None,
            }),
        )]),
        carbide_api_url: format!("https://{}:{}", api_addr.ip(), api_addr.port()),
        log_file: None,
        use_pxe_api: true,
        pxe_server_host: None,
        pxe_server_port: None,
        bmc_mock_port: 0, // unused, we're using dynamic ports on localhost
        dhcp_server_address: None,
        interface: String::from("UNUSED"), // unused, we're using dynamic ports on localhost
        tui_enabled: false,
        sudo_command: None,
        use_dhcp_api: true,
        use_single_bmc_mock: false, // unused, we're constructing machines ourselves
        configure_carbide_bmc_proxy_host: None,
        persist_dir: None,
        cleanup_on_quit: false,
        api_refresh_interval: Duration::from_millis(500),
        mock_bmc_ssh_server: false,
        mock_bmc_ssh_port: None,
    };

    let (machine_handles, _mat_handle) = api_test_helper::machine_a_tron::run_local(
        mat_config,
        additional_api_urls,
        &test_env.root_dir,
        Some(bmc_mock_registry.clone()),
    )
    .await
    .unwrap();

    let results = join_all(machine_handles.into_iter().map(run_assertions)).await;
    assert_eq!(results.len(), host_count as usize);

    results.into_iter().try_collect()
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
    txn.commit().await.unwrap();
    rows.try_get("row_cnt").unwrap()
}
