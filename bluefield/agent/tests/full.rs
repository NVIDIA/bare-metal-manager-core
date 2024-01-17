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

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs};

use axum::extract::State as AxumState;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use eyre::WrapErr;
use tokio::sync::Mutex;

mod common;

// TODO: Add settings to config file and switch this to true
// Then assert that it works
const TEST_METADATA_SERVICE: bool = false;

const AGENT_CONFIG: &str = r#"
[forge-system]
api-server = "https://$API_SERVER"
pxe-server = "http://127.0.0.1:8080"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
is-fake-dpu = true
interface-id = "f377ed72-d912-4879-958a-8d1f82a50d62"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.example.com"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = true

[period]
main-loop-active-secs = 1
network-config-fetch-secs = 1
main-loop-idle-secs = 30
version-check-secs = 1800
"#;

#[derive(Default)]
struct State {
    is_nvue: bool,
    has_discovered: bool,
    has_checked_for_upgrade: bool,
    has_fetched_netconf: bool,
    has_reported_health: bool,
}

#[derive(Default, Debug)]
struct TestOut {
    is_skip: bool,
    hbn_root_dir: Option<tempfile::TempDir>,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_etv() -> eyre::Result<()> {
    let out = run_common_parts(false).await?;
    if out.is_skip {
        return Ok(());
    }

    // The files were written
    let td = out.hbn_root_dir.unwrap();
    let hbn_root = td.path();
    assert!(hbn_root.join("etc/frr/frr.conf").exists());
    assert!(hbn_root.join("etc/network/interfaces").exists());
    assert!(hbn_root
        .join("etc/supervisor/conf.d/default-isc-dhcp-relay.conf")
        .exists());
    assert!(hbn_root
        .join("etc/cumulus/acl/policy.d/60-forge.rules")
        .exists());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_nvue() -> eyre::Result<()> {
    let out = run_common_parts(true).await?;
    if out.is_skip {
        return Ok(());
    }

    // The files were written
    let td = out.hbn_root_dir.unwrap();
    let hbn_root = td.path();
    let startup_yaml = hbn_root.join("etc/nvue.d/startup.yaml");
    assert!(startup_yaml.exists());

    // Check it's YAML
    const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
    let startup_yaml = fs::read_to_string(startup_yaml)?;
    let yaml_obj: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
        .map_err(|err| {
            let mut f = fs::File::create(ERR_FILE).unwrap();
            f.write_all(startup_yaml.as_bytes()).unwrap();
            err
        })
        .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;
    assert_eq!(yaml_obj.len(), 2); // 'header' and 'set'

    Ok(())
}

// Most of the test is shared between ETV files and ETV NVUE
async fn run_common_parts(is_nvue: bool) -> eyre::Result<TestOut> {
    forge_host_support::init_logging()?;
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    env::set_var("IGNORE_MGMT_VRF", "true");

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        tracing::warn!(
            "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
        );
        return Ok(TestOut{is_skip: true, ..Default::default()});
    };
    let root_dir = PathBuf::from(repo_root);

    let td = tempfile::tempdir()?;
    let hbn_root = td.path();
    fs::create_dir_all(hbn_root.join("etc/frr"))?;
    fs::create_dir_all(hbn_root.join("etc/network"))?;
    fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;
    fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;
    fs::create_dir_all(hbn_root.join("etc/nvue.d"))?;

    let state: Arc<Mutex<State>> = Arc::new(Mutex::new(Default::default()));
    state.lock().await.is_nvue = is_nvue;

    // Start carbide API
    let app = Router::new()
        .route("/forge.Forge/DiscoverMachine", post(handle_discover))
        .route(
            "/forge.Forge/GetManagedHostNetworkConfig",
            post(handle_netconf),
        )
        .route(
            "/forge.Forge/RecordDpuNetworkStatus",
            post(handle_record_netstat),
        )
        .route(
            "/forge.Forge/DpuAgentUpgradeCheck",
            post(handle_dpu_agent_upgrade_check),
        )
        .fallback(handler)
        .with_state(state.clone());
    let (addr, join_handle) = common::run_grpc_server(app).await?;

    let cfg = AGENT_CONFIG
        .replace("$ROOT_DIR", &root_dir.display().to_string())
        .replace("$HBN_ROOT", &hbn_root.display().to_string())
        .replace("$API_SERVER", &addr.to_string());

    let agent_config_file = tempfile::NamedTempFile::new()?;
    fs::write(agent_config_file.path(), cfg)?;
    let opts = agent::Options {
        version: false,
        config_path: agent_config_file.path().to_path_buf(),
        cmd: Some(agent::AgentCommand::Run(agent::RunOptions {
            enable_metadata_service: TEST_METADATA_SERVICE,
            override_machine_id: None,
        })),
    };

    // Put our fake `crictl` on front of path so that HBN health checks succeed
    let dev_bin = root_dir.join("dev/bin");
    if let Some(path) = env::var_os("PATH") {
        let mut paths = env::split_paths(&path).collect::<Vec<_>>();
        paths.insert(0, dev_bin);
        let new_path = env::join_paths(paths)?;
        env::set_var("PATH", new_path);
    }

    // Start forge-dpu-agent
    tokio::spawn(async move {
        if let Err(e) = agent::start(opts).await {
            tracing::error!("Failed to start DPU agent: {}", e);
        }
    });

    // Let it run twice
    // First time it noticed HBN is up. Second time it applies config.
    // In config above period.main_loop_active_secs is 1 seconds, so make this 2 seconds
    tokio::time::sleep(Duration::from_secs(2)).await;

    join_handle.abort();

    // The gRPC calls were made
    let statel = state.lock().await;
    assert!(statel.has_discovered);
    assert!(statel.has_checked_for_upgrade);
    assert!(statel.has_fetched_netconf);
    assert!(statel.has_reported_health);

    Ok(TestOut {
        is_skip: false,
        hbn_root_dir: Some(td),
    })
}

async fn handle_discover(AxumState(state): AxumState<Arc<Mutex<State>>>) -> impl IntoResponse {
    state.lock().await.has_discovered = true;
    common::respond(rpc::forge::MachineDiscoveryResult {
        machine_id: Some(
            "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g"
                .to_string()
                .into(),
        ),
        machine_certificate: None,
    })
}

async fn handle_netconf(AxumState(state): AxumState<Arc<Mutex<State>>>) -> impl IntoResponse {
    state.lock().await.has_fetched_netconf = true;
    let is_nvue = state.lock().await.is_nvue;
    let config_version = format!("V{}-T{}", 1, now().timestamp_micros());
    let admin_interface = rpc::forge::FlatInterfaceConfig {
        function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
        vlan_id: 10,
        vni: 10100,
        gateway: "192.168.0.0/16".to_string(),
        ip: "127.0.0.1".to_string(),
        virtual_function_id: None,
        vpc_prefixes: vec![],
        prefix: "127.0.0.1/32".to_string(),
        fqdn: "host1".to_string(),
        booturl: None,
    };

    let netconf = rpc::forge::ManagedHostNetworkConfigResponse {
        is_production_mode: true,
        asn: 65535,
        dhcp_servers: vec!["127.0.0.1".to_string()],
        vni_device: "".to_string(),

        managed_host_config: Some(rpc::forge::ManagedHostNetworkConfig {
            loopback_ip: "127.0.0.1".to_string(),
        }),
        managed_host_config_version: config_version.clone(),
        use_admin_network: true,
        admin_interface: Some(admin_interface),
        tenant_interfaces: vec![],
        instance_config_version: config_version,
        instance_id: None,
        network_virtualization_type: if is_nvue {
            Some(rpc::forge::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32)
        } else {
            // EthernetVirtualizer is the default
            None
        },
        vpc_vni: None,
        route_servers: vec![],
        remote_id: "".to_string(),
        deny_prefixes: vec![],
        enable_dhcp: false,
        host_interface_id: None,
    };
    common::respond(netconf)
}

async fn handle_record_netstat(
    AxumState(state): AxumState<Arc<Mutex<State>>>,
) -> impl IntoResponse {
    state.lock().await.has_reported_health = true;
    common::respond(())
}

async fn handle_dpu_agent_upgrade_check(
    AxumState(state): AxumState<Arc<Mutex<State>>>,
) -> impl axum::response::IntoResponse {
    state.lock().await.has_checked_for_upgrade = true;
    common::respond(rpc::forge::DpuAgentUpgradeCheckResponse {
        should_upgrade: false,
        package_version: forge_version::v!(build_version)[1..].to_string(),
        server_version: forge_version::v!(build_version).to_string(),
    })
}

async fn handler(uri: Uri) -> impl IntoResponse {
    tracing::debug!("general handler: {:?}", uri);
    StatusCode::NOT_FOUND
}

// copied from api/src/model/config_version.rs
fn now() -> DateTime<Utc> {
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch");
    let round = now.as_nanos() % 1000;
    now -= Duration::from_nanos(round as _);

    let naive = NaiveDateTime::from_timestamp_opt(now.as_secs() as i64, now.subsec_nanos())
        .expect("out-of-range number of seconds and/or invalid nanosecond");
    Utc.from_utc_datetime(&naive)
}
