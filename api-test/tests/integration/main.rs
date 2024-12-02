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
use std::future::Future;
use std::net::TcpListener;
use std::str::FromStr;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::{self, PathBuf},
    time::{self, Duration},
};

use crate::utils::IntegrationTestEnvironment;
use ::machine_a_tron::{BmcMockRegistry, HostMachineActor, MachineATronConfig, MachineConfig};
use ::utils::HostPortPair;
use bmc_mock::ListenerOrAddress;
use futures::future::join_all;
use futures::FutureExt;
use grpcurl::grpcurl;
use host::machine_validation_completed;
use itertools::Itertools;
use sqlx::types::mac_address::MacAddress;
use sqlx::{Postgres, Row};
use tokio::sync::RwLock;
use tokio::time::sleep;

mod api_server;
mod domain;
mod dpu;
pub mod grpcurl;
mod host;
mod instance;
mod machine;
mod machine_a_tron;
mod metrics;
mod subnet;
mod upgrade;
mod utils;
mod vault;
mod vpc;

/// Setup logging for tests.
#[ctor::ctor]
fn setup_test_logging() {
    use tracing_subscriber::util::SubscriberInitExt;
    let logging = carbide::test_logging::test_logging_subscriber();
    if let Err(e) = logging.try_init() {
        // Note: Resist the temptation to ignore this error. We really should only have one place in
        // the test binary that initializes logging.
        panic!(
            "Failed to initialize trace logging for tests. It's possible some earlier code path \
        has already set a global default log subscriber: {e}"
        );
    }
}

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
        metrics: _,
        db_url: _,
    } = test_env.clone();

    // Run bmc-mock
    let routers = HashMap::from([(
        "".to_owned(),
        bmc_mock::default_host_tar_router(false, None),
    )]);
    let mut bmc_mock_handle =
        bmc_mock::run_combined_mock::<String>(Arc::new(RwLock::new(routers)), None, None).await?;

    let server_handle = utils::start_api_server(
        test_env, None,
        // TODO: enabling create_machines in site explorer causes failures
        // it appears parts of this test were written without create_machines in mind
        false,
    )
    .await?;

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
    let domain_id = domain::create(carbide_api_addr, "tenant-1.local")?;
    let segment_id = subnet::create(carbide_api_addr, &vpc_id, &domain_id, 10, false)?;

    // Create instance with phone_home enabled

    let instance_id = instance::create(
        carbide_api_addr,
        &host_machine_id,
        &segment_id,
        Some("test"),
        true,
        true,
    )?;
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

    instance::release(carbide_api_addr, &host_machine_id, &instance_id, true)?;

    let metrics = metrics::wait_for_metric_line(carbide_metrics_addr, r#"forge_machines_per_state{fresh="true",state="waitingforcleanup",substate="hostcleanup"} 1"#).await?;
    metrics::assert_metric_line(&metrics, r#"forge_machines_total{fresh="true"} 1"#);

    machine::cleanup_completed(carbide_api_addr, &host_machine_id)?;

    machine::wait_for_state(
        carbide_api_addr,
        &host_machine_id,
        "HostInitializing/MachineValidating",
    )?;

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
    bmc_mock_handle.stop().await?;
    server_handle.stop().await?;
    db_pool.close().await;
    Ok(())
}

/// Run multiple machine-a-tron integration tests in parallel against a shared carbide API instance.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial] // These tests drop/create a postgres database, prevent them from running concurrently
async fn test_integration_machine_a_tron() -> eyre::Result<()> {
    let Some(test_env) = IntegrationTestEnvironment::try_from_environment().await? else {
        return Ok(());
    };

    let carbide_api_addr = test_env.carbide_api_addr;

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = PathBuf::from(format!("{}/dev/bmc-mock", test_env.root_dir.display()));
    let mut bmc_mock_handle = bmc_mock::run_combined_mock(
        bmc_address_registry.clone(),
        Some(certs_dir),
        Some(ListenerOrAddress::Listener(
            // let OS choose available port
            TcpListener::bind("127.0.0.1:0")?,
        )),
    )
    .await?;

    // Begin the integration test by starting an API server. This will be shared between multiple
    // individual machine-a-tron-based tests, which can run in parallel against the same instance.
    let server_handle = utils::start_api_server(
        test_env.clone(),
        Some(HostPortPair::HostAndPort(
            "127.0.0.1".to_string(),
            bmc_mock_handle.address.port(),
        )),
        true,
    )
    .await?;

    let tenant1_vpc = vpc::create(carbide_api_addr)?;
    let domain_id = domain::create(carbide_api_addr, "tenant-1.local")?;
    let managed_segment_id = subnet::create(carbide_api_addr, &tenant1_vpc, &domain_id, 10, false)?;
    let host_inband_segment_id =
        subnet::create(carbide_api_addr, &tenant1_vpc, &domain_id, 11, true)?;

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
            &host_inband_segment_id,
            // Relay IP in host-inband net
            Ipv4Addr::new(10, 10, 11, 2),
        )
        .boxed(),
        test_machine_a_tron_singledpu_nic_mode(
            &test_env,
            &bmc_address_registry,
            &host_inband_segment_id,
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

    server_handle.stop().await?;
    test_env.db_pool.close().await;
    bmc_mock_handle.stop().await?;
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
        |machine_actor| {
            let segment_id = segment_id.to_string();
            let carbide_api_addr = test_env.carbide_api_addr;
            async move {
                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                let machine_id = machine_actor
                    .observed_machine_id()
                    .await?
                    .expect("Machine ID should be set if host is ready")
                    .to_string();
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                let instance_id = instance::create(
                    carbide_api_addr,
                    &machine_id,
                    &segment_id,
                    None,
                    false,
                    false,
                )?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Assigned/Ready")
                    .await?;

                let instance_json = instance::get_instance_json_by_machine_id(
                    carbide_api_addr,
                    machine_actor
                        .observed_machine_id()
                        .await?
                        .expect("HostMachine should have a Machine ID once it's in ready state")
                        .to_string()
                        .as_str(),
                )?;
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
                instance::release(carbide_api_addr, &machine_id, &instance_id, false)?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
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
    segment_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        1,
        0,
        false,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_actor| {
            let carbide_api_addr = test_env.carbide_api_addr;
            async move {
                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                let machine_id = machine_actor
                    .observed_machine_id()
                    .await?
                    .expect("Machine ID should be set if host is ready")
                    .to_string();
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                let instance_id = instance::create(
                    carbide_api_addr,
                    &machine_id,
                    segment_id,
                    None,
                    false,
                    false,
                )?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Assigned/Ready")
                    .await?;

                let instance_json = instance::get_instance_json_by_machine_id(
                    carbide_api_addr,
                    machine_actor
                        .observed_machine_id()
                        .await?
                        .expect("HostMachine should have a Machine ID once it's in ready state")
                        .to_string()
                        .as_str(),
                )?;
                let serde_json::Value::Object(interface) =
                    &instance_json["instances"][0]["status"]["network"]["interfaces"][0]
                else {
                    panic!("Allocated instance does not have interface configuration")
                };

                let serde_json::Value::Array(addrs) = &interface["addresses"] else {
                    panic!("Interface does not have addresses")
                };
                assert_eq!(addrs.len(), 1, "Interface should have a single address");

                let serde_json::Value::String(mac_address) = &interface["macAddress"] else {
                    panic!("Interface does not have MAC address set")
                };
                if let Err(e) = MacAddress::from_str(mac_address.as_str()) {
                    panic!("Invalid mac address: {mac_address}: {e}");
                };
                let serde_json::Value::Array(gateways) = &interface["gateways"] else {
                    panic!("Interface does not have gateways set")
                };
                assert_eq!(gateways.len(), 1, "Interface should have a single gateway");

                tracing::info!(
                    "Machine {machine_id} has made it to Assigned/Ready, releasing instance"
                );
                instance::release(carbide_api_addr, &machine_id, &instance_id, false)?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                tracing::info!("Machine {machine_id} has made it to Ready again, all done");
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_singledpu_nic_mode(
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    segment_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        1,
        1,
        true,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_actor| {
            let segment_id = segment_id.to_string();
            let carbide_api_addr = test_env.carbide_api_addr;
            async move {
                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                let machine_id = machine_actor
                    .observed_machine_id()
                    .await?
                    .expect("Machine ID should be set if host is ready")
                    .to_string();
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                let instance_id = instance::create(
                    carbide_api_addr,
                    &machine_id,
                    &segment_id,
                    None,
                    false,
                    false,
                )?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Assigned/Ready")
                    .await?;

                let instance_json = instance::get_instance_json_by_machine_id(
                    carbide_api_addr,
                    machine_actor
                        .observed_machine_id()
                        .await?
                        .expect("HostMachine should have a Machine ID once it's in ready state")
                        .to_string()
                        .as_str(),
                )?;
                let serde_json::Value::Object(interface) =
                    &instance_json["instances"][0]["status"]["network"]["interfaces"][0]
                else {
                    panic!("Allocated instance does not have interface configuration")
                };

                let serde_json::Value::Array(addrs) = &interface["addresses"] else {
                    panic!("Interface does not have addresses")
                };
                assert_eq!(addrs.len(), 1, "Interface should have a single address");

                let serde_json::Value::String(mac_address) = &interface["macAddress"] else {
                    panic!("Interface does not have MAC address set")
                };
                if let Err(e) = MacAddress::from_str(mac_address.as_str()) {
                    panic!("Invalid mac address: {mac_address}: {e}");
                };
                let serde_json::Value::Array(gateways) = &interface["gateways"] else {
                    panic!("Interface does not have gateways set")
                };
                assert_eq!(gateways.len(), 1, "Interface should have a single gateway");

                tracing::info!(
                    "Machine {machine_id} has made it to Assigned/Ready, releasing instance"
                );
                instance::release(carbide_api_addr, &machine_id, &instance_id, false)?;

                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                tracing::info!("Machine {machine_id} has made it to Ready again, all done");
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
    F: Fn(HostMachineActor) -> O,
    O: Future<Output = eyre::Result<()>>,
{
    let mat_config = MachineATronConfig {
        machines: BTreeMap::from([(
            "config".to_string(),
            MachineConfig {
                host_count,
                dpu_per_host_count,
                boot_delay: 1,
                dpu_reboot_delay: 1,
                host_reboot_delay: 1,
                template_dir: test_env
                    .root_dir
                    .join("dev/machine-a-tron/templates")
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
            },
        )]),
        carbide_api_url: Some(format!(
            "https://{}:{}",
            test_env.carbide_api_addr.ip(),
            test_env.carbide_api_addr.port()
        )),
        log_file: None,
        bmc_mock_host_tar: PathBuf::from(format!(
            "{}/dev/bmc-mock/dell_poweredge_r750.tar.gz",
            test_env.root_dir.to_string_lossy()
        )),
        bmc_mock_dpu_tar: PathBuf::from(format!(
            "{}/dev/bmc-mock/nvidia_dpu.tar.gz",
            test_env.root_dir.to_string_lossy()
        )),
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
    };

    let (machine_actors, mat_handle) = machine_a_tron::run_local(
        mat_config,
        test_env.root_dir.clone(),
        bmc_mock_registry.clone(),
    )
    .await
    .unwrap();

    let results = join_all(machine_actors.into_iter().map(run_assertions)).await;
    assert_eq!(results.len(), host_count as usize);
    mat_handle.stop().await?;

    results.into_iter().try_collect()
}

/// Bootstraps a Host in `ready` state. Returns the `machine_id`
async fn host_boostrap(carbide_api_addr: SocketAddr) -> eyre::Result<String> {
    let host_machine_id = host::bootstrap(carbide_api_addr)?;

    // Wait until carbide-api is prepared to admit the DPU might have rebooted.
    // There are hard coded sleeps in carbide-api before this happens.
    machine::wait_for_state(carbide_api_addr, &host_machine_id, "WaitForDPUUp")?;

    machine::wait_for_state(
        carbide_api_addr,
        &host_machine_id,
        "HostInitializing/MachineValidating",
    )?;

    machine_validation_completed(carbide_api_addr, &host_machine_id)?;

    // After DPU reboot forge_dpu_agent reports health to carbide-api, triggering state transition
    machine::wait_for_state(
        carbide_api_addr,
        &host_machine_id,
        "HostInitializing/Discovered",
    )?;

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
