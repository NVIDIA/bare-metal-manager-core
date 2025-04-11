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

use forge_network::virtualization::get_svi_ip;

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::tests::common;
use crate::util::compare_lines;
use axum::Router;
use axum::extract::State as AxumState;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use chrono::{DateTime, TimeZone, Utc};
use eyre::WrapErr;
use forge_network::virtualization::VpcVirtualizationType;
use ipnetwork::IpNetwork;
use rpc::forge::{DpuInfo, FlatInterfaceNetworkSecurityGroupConfig};
use tokio::sync::Mutex;

#[derive(Default, Debug)]
struct State {
    has_discovered: bool,
    has_checked_for_upgrade: bool,
    num_netconf_fetches: AtomicUsize,
    num_health_reports: AtomicUsize,
    num_get_dpu_ips: AtomicUsize,
    virtualization_type: VpcVirtualizationType,
}

#[derive(Default, Debug)]
struct TestOut {
    is_skip: bool,
    hbn_root_dir: Option<tempfile::TempDir>,
}

// test_etv is different than the other tests (which all leverage
// test_nvue_generic), because it writes out a bunch of additional
// files (vs. the nvue-based mechanism, which just provides us with
// a single nvue_startup.yaml config).
#[tokio::test(flavor = "multi_thread")]
pub async fn test_etv() -> eyre::Result<()> {
    let out = run_common_parts(VpcVirtualizationType::EthernetVirtualizer).await?;
    if out.is_skip {
        return Ok(());
    }

    // Make sure all of the files that we expect (in the non-nvue
    // world) are being written out.
    let td = out.hbn_root_dir.unwrap();
    let hbn_root = td.path();
    assert!(hbn_root.join("etc/frr/frr.conf").exists());
    assert!(hbn_root.join("etc/network/interfaces").exists());
    assert!(
        hbn_root
            .join("etc/supervisor/conf.d/default-isc-dhcp-relay.conf")
            .exists()
    );
    assert!(
        hbn_root
            .join("etc/cumulus/acl/policy.d/60-forge.rules")
            .exists()
    );

    Ok(())
}

// test_etv_nvue tests that config is being generated successfully
// for the OG networking config, but using nvue templating mechanism.
// NOTE: This is currently a _very_ light test because it takes the
// UseAdminNetwork paths in the template, which leaves out a lot
// of config.  Some of what's missing seems to be covered in
// ethernet_virtualization tests, though.
#[tokio::test(flavor = "multi_thread")]
async fn test_etv_nvue() -> eyre::Result<()> {
    let expected = include_str!("../../templates/tests/full_nvue_startup_etv.yaml.expected");
    test_nvue_generic(VpcVirtualizationType::EthernetVirtualizerWithNvue, expected).await
}

// test_fnn_l3 tests that config is being generated successfully
// via nvue templating against the FNN L3 template.
#[tokio::test(flavor = "multi_thread")]
async fn test_fnn_l3() -> eyre::Result<()> {
    let expected = include_str!("../../templates/tests/full_nvue_startup_fnn_l3.yaml.expected");
    test_nvue_generic(VpcVirtualizationType::Fnn, expected).await
}

// All of the new tests are leveraging nvue for configs, regardless
// of template, so have a test_nvue_generic that just takes a virtualization
// type.
async fn test_nvue_generic(
    virtualization_type: VpcVirtualizationType,
    expected: &str,
) -> eyre::Result<()> {
    let out = run_common_parts(virtualization_type).await?;
    if out.is_skip {
        return Ok(());
    }

    // Make sure the nvue startup file was written where
    // it was supposed to be written (crate::nvue::PATH
    // within the test-specific temp dir).
    let td = out.hbn_root_dir.unwrap();
    let hbn_root = td.path();
    let startup_yaml = hbn_root.join(crate::nvue::PATH);
    assert!(
        startup_yaml.exists(),
        "could not find {} startup_yaml at path: {:?}",
        virtualization_type,
        startup_yaml.to_str()
    );

    // And now check that the output nvue config YAML
    // is actually valid YAML. If it's not, write out
    // whatever the error is to ERR_FILE, so we can go
    // check and see what's up.
    const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
    let startup_yaml = fs::read_to_string(startup_yaml)?;
    let yaml_obj: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
        .inspect_err(|_| {
            let mut f = fs::File::create(ERR_FILE).unwrap();
            f.write_all(startup_yaml.as_bytes()).unwrap();
        })
        .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;
    assert_eq!(yaml_obj.len(), 2); // 'header' and 'set'

    let r = compare_lines(startup_yaml.as_str(), expected, None);
    eprint!("Diff output:\n{}", r.report());
    assert!(
        r.is_identical(),
        "generated startup_yaml does not match expected startup_yaml for {}",
        virtualization_type
    );

    Ok(())
}

// run_common_parts exists, because most of the test is
// shared between the [legacy] ETV files mechanism and the
// new nvue templating mechanism.
async fn run_common_parts(virtualization_type: VpcVirtualizationType) -> eyre::Result<TestOut> {
    forge_host_support::init_logging()?;

    let state: Arc<Mutex<State>> = Arc::new(Mutex::new(Default::default()));
    state.lock().await.virtualization_type = virtualization_type;

    // Simulate a local carbide-api by initializing a new axum::Router that exposes the
    // same gRPC endpoints that Carbide API would (and, in this case, the exact gRPC
    // endpoints that our local agent that we're spawning will need to make calls to).
    // A `state` is provided to the Router so that each mocked call (e.g. how `handle_netconf
    // is leveraged for `/forge.Forge/GetManagedHostNetworkConfig` calls) can have
    // additional bits of context (just like carbide-api would).
    let app = Router::new()
        .route("/up", get(handle_up))
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
        .route(
            "/forge.Forge/UpdateAgentReportedInventory",
            post(handle_update_agent_reported_inventory),
        )
        .route(
            "/forge.Forge/GetDpuInfoList",
            post(handle_get_dpu_info_list),
        )
        // ForgeApiClient needs a working Version route for connection retrying
        .route("/forge.Forge/Version", post(handle_version))
        .fallback(handler)
        .with_state(state.clone());
    let (addr, join_handle) = common::run_grpc_server(app).await?;

    let td: tempfile::TempDir = tempfile::tempdir()?;
    let agent_config_file = tempfile::NamedTempFile::new()?;
    let opts = match common::setup_agent_run_env(&addr, &td, &agent_config_file) {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            return Ok(TestOut {
                is_skip: true,
                ..Default::default()
            });
        }
        Err(e) => {
            return Err(e);
        }
    };

    // Start forge-dpu-agent
    tokio::spawn(async move {
        if let Err(e) = crate::start(opts).await {
            tracing::error!("Failed to start DPU agent: {:#}", e);
        }
    });

    // Wait until we report health at least 2 times
    // At that point in time the first configuration should have been applied
    // and the check for updates should have occured
    let start = std::time::Instant::now();
    loop {
        let statel = state.lock().await;
        if statel.num_health_reports.load(Ordering::SeqCst) > 1 {
            break;
        }

        if start.elapsed() > std::time::Duration::from_secs(30) {
            return Err(eyre::eyre!(
                "Health report was not sent 2 times in 30s. State: {:?}",
                statel
            ));
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    join_handle.abort();

    // The gRPC calls were made
    let statel = state.lock().await;
    assert!(statel.has_discovered);
    assert!(statel.has_checked_for_upgrade);
    assert!(statel.num_health_reports.load(Ordering::SeqCst) > 1);
    // Since Network config fetching runs in a separate task, it might not have
    // happened 2 times but just a single time
    assert!(statel.num_netconf_fetches.load(Ordering::SeqCst) > 0);
    assert!(statel.num_get_dpu_ips.load(Ordering::SeqCst) > 0);
    Ok(TestOut {
        is_skip: false,
        hbn_root_dir: Some(td),
    })
}

/// Health check. When this responds we know the mock server is ready.
async fn handle_up() -> &'static str {
    "OK"
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
        attest_key_challenge: None,
    })
}

async fn handle_version() -> impl IntoResponse {
    common::respond(rpc::forge::BuildInfo::default())
}

async fn handle_netconf(AxumState(state): AxumState<Arc<Mutex<State>>>) -> impl IntoResponse {
    {
        state
            .lock()
            .await
            .num_netconf_fetches
            .fetch_add(1, Ordering::SeqCst);
    }
    let virtualization_type = state.lock().await.virtualization_type;
    let config_version = format!("V{}-T{}", 1, now().timestamp_micros());

    let vpc_peer_prefixes = match virtualization_type {
        VpcVirtualizationType::EthernetVirtualizer
        | VpcVirtualizationType::EthernetVirtualizerWithNvue => {
            vec!["10.217.6.176/29".to_string()]
        }
        VpcVirtualizationType::Fnn => {
            vec![]
        }
    };

    let vpc_peer_vnis = match virtualization_type {
        VpcVirtualizationType::EthernetVirtualizer
        | VpcVirtualizationType::EthernetVirtualizerWithNvue => {
            vec![]
        }
        VpcVirtualizationType::Fnn => {
            println!("Setting vpc_peer_vnis to fnn");
            vec![1025186, 1025197]
        }
    };

    let admin_interface_prefix: IpNetwork = "192.168.0.12/32".parse().unwrap();
    let svi_ip = IpAddr::from_str("192.168.0.3").unwrap();

    let admin_interface = rpc::forge::FlatInterfaceConfig {
        function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
        vlan_id: 10,
        vni: 10100,
        vpc_vni: 10101,
        gateway: "192.168.0.0/16".to_string(),
        ip: "192.168.0.12".to_string(),
        interface_prefix: admin_interface_prefix.to_string(),
        virtual_function_id: None,
        vpc_prefixes: vec![],
        vpc_peer_prefixes: vec![],
        vpc_peer_vnis: vec![1025186, 1025197],
        prefix: "192.168.0.1/32".to_string(),
        fqdn: "host1".to_string(),
        booturl: None,
        svi_ip: get_svi_ip(&Some(svi_ip), virtualization_type, false, 28)
            .unwrap()
            .map(|ip| ip.to_string()),
        tenant_vrf_loopback_ip: Some("10.1.1.1".to_string()),
        is_l2_segment: false,
        network_security_group: None,
    };
    assert_eq!(admin_interface.svi_ip, None);

    let tenant_interface_prefix: IpNetwork = "192.168.1.12/32".parse().unwrap();

    let tenant_interface = rpc::forge::FlatInterfaceConfig {
        function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
        vlan_id: 10,
        vni: 10100,
        vpc_vni: 10101,
        gateway: "192.168.1.0/16".to_string(),
        ip: "192.168.1.12".to_string(),
        interface_prefix: tenant_interface_prefix.to_string(),
        virtual_function_id: None,
        vpc_prefixes: vec![],
        vpc_peer_prefixes,
        vpc_peer_vnis,
        prefix: "192.168.1.1/32".to_string(),
        fqdn: "host1".to_string(),
        booturl: None,
        svi_ip: get_svi_ip(&Some(svi_ip), virtualization_type, false, 28)
            .unwrap()
            .map(|ip| ip.to_string()),
        tenant_vrf_loopback_ip: Some("10.1.1.1".to_string()),
        is_l2_segment: false,
        network_security_group: Some(FlatInterfaceNetworkSecurityGroupConfig {
            id: "5b931164-d9c6-11ef-8292-232e57575621".to_string(),
            version: "V1-1".to_string(),
            source: rpc::forge::NetworkSecurityGroupSource::NsgSourceVpc.into(),
            rules: vec![rpc::forge::ResolvedNetworkSecurityGroupRule {
                src_prefixes: vec!["0.0.0.0/0".to_string()],
                dst_prefixes: vec!["0.0.0.0/0".to_string()],
                rule: Some(rpc::forge::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                        .into(),
                    ipv6: false,
                    src_port_start: Some(80),
                    src_port_end: Some(81),
                    dst_port_start: Some(80),
                    dst_port_end: Some(81),
                    protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 9001,
                    source_net: Some(
                        rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                }),
            },                    rpc::forge::ResolvedNetworkSecurityGroupRule {
                src_prefixes: vec!["0.0.0.0/0".to_string()],
                dst_prefixes: vec!["1.0.0.0/0".to_string()],
                rule: Some(rpc::forge::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                        .into(),
                    ipv6: false,
                    src_port_start: Some(80),
                    src_port_end: Some(81),
                    dst_port_start: Some(80),
                    dst_port_end: Some(81),
                    protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 9001,
                    source_net: Some(
                        rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "1.0.0.0/0".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "1.0.0.0/0".to_string(),
                        ),
                    ),
                }),
            },
            rpc::forge::ResolvedNetworkSecurityGroupRule {
                src_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:8888/128".to_string()],
                dst_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:9999/128".to_string()],
                rule: Some(rpc::forge::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                        .into(),
                    ipv6: true,
                    src_port_start: Some(80),
                    src_port_end: Some(81),
                    dst_port_start: Some(80),
                    dst_port_end: Some(81),
                    protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 9001,
                    source_net: Some(
                        rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "2001:db8:3333:4444:5555:6666:7777:8888/128".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "2001:db8:3333:4444:5555:6666:7777:9999/128".to_string(),
                        ),
                    ),
                }),
            },                    rpc::forge::ResolvedNetworkSecurityGroupRule {
                src_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:8888/128".to_string()],
                dst_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:9999/128".to_string()],
                rule: Some(rpc::forge::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                        .into(),
                    ipv6: true,
                    src_port_start: Some(80),
                    src_port_end: Some(81),
                    dst_port_start: Some(80),
                    dst_port_end: Some(81),
                    protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 9001,
                    source_net: Some(
                        rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "2001:db8:3333:4444:5555:6666:7777:8888/128".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "2001:db8:3333:4444:5555:6666:7777:9999/128".to_string(),
                        ),
                    ),
                }),
            }],
        }),
    };

    let netconf = rpc::forge::ManagedHostNetworkConfigResponse {
        asn: 65535,
        dhcp_servers: vec!["127.0.0.1".to_string()],
        vni_device: "".to_string(),

        managed_host_config: Some(rpc::forge::ManagedHostNetworkConfig {
            loopback_ip: "127.0.0.1".to_string(),
            quarantine_state: None,
        }),
        managed_host_config_version: config_version.clone(),
        use_admin_network: true,
        admin_interface: Some(admin_interface),
        tenant_interfaces: vec![tenant_interface],
        instance_network_config_version: config_version,
        instance_id: None,
        network_virtualization_type: Some(
            rpc::forge::VpcVirtualizationType::from(virtualization_type).into(),
        ),
        vpc_vni: None,
        route_servers: vec![],
        remote_id: "".to_string(),
        deny_prefixes: vec!["1.1.1.1/32".to_string()],
        site_fabric_prefixes: vec!["2.2.2.2/32".to_string()],
        vpc_isolation_behavior: rpc::forge::VpcIsolationBehaviorType::VpcIsolationMutual.into(),
        deprecated_deny_prefixes: vec![],
        enable_dhcp: true,
        host_interface_id: None,
        min_dpu_functioning_links: None,
        is_primary_dpu: true,
        multidpu_enabled: false,
        dpu_network_pinger_type: Some("HbnExec".to_string()),
        internet_l3_vni: Some(1337),
        stateful_acls_enabled: true,
    };
    common::respond(netconf)
}

async fn handle_record_netstat(
    AxumState(state): AxumState<Arc<Mutex<State>>>,
) -> impl IntoResponse {
    {
        state
            .lock()
            .await
            .num_health_reports
            .fetch_add(1, Ordering::SeqCst);
    }
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

async fn handle_update_agent_reported_inventory() -> impl axum::response::IntoResponse {
    common::respond(())
}

async fn handle_get_dpu_info_list(
    AxumState(state): AxumState<Arc<Mutex<State>>>,
) -> impl axum::response::IntoResponse {
    {
        state
            .lock()
            .await
            .num_get_dpu_ips
            .fetch_add(1, Ordering::SeqCst);
    }
    common::respond(rpc::forge::GetDpuInfoListResponse {
        dpu_list: vec![
            DpuInfo {
                id: "fm100dsvstfujf6mis0gpsoi81tadmllicv7rqo4s7gc16gi0t2478672vg".to_string(),
                loopback_ip: "172.20.0.119".to_string(),
            },
            DpuInfo {
                id: "fm100dsjd1vuk6gklgvh0ao8t7r7tk1pt101ub5ck0g3j7lqcm8h3rf1p8g".to_string(),
                loopback_ip: "172.20.0.200".to_string(),
            },
        ],
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

    let naive = DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
        .expect("out-of-range number of seconds and/or invalid nanosecond");
    Utc.from_utc_datetime(&naive.naive_utc())
}
