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
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{self, Duration};

use ::carbide_utils::HostPortPair;
use ::machine_a_tron::{
    BmcMockRegistry, HostMachineHandle, MachineATronConfig, MachineConfig, RackConfig,
};
use api_test_helper::{
    IntegrationTestEnvironment, domain, instance, machine, metrics, subnet, tenant, utils, vpc,
    vpc_prefix,
};
use bmc_mock::test_support::TEST_MAC_POOL;
use bmc_mock::{HostHardwareType, ListenerOrAddress};
use carbide_uuid::rack::{RackId, RackProfileId};
use eyre::ContextCompat;
use futures::FutureExt;
use futures::future::join_all;
use itertools::Itertools;
use sqlx::{Postgres, Row};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

#[ctor::ctor(unsafe)]
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
        println!("test_integration: SKIPPED (set REPO_ROOT and DATABASE_URL to run)");
        return Ok(());
    };

    let carbide_api_addrs = &test_env.carbide_api_addrs;

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = PathBuf::from(format!("{}/crates/bmc-mock", test_env.root_dir.display()));
    let server_config = bmc_mock::tls::server_config(Some(certs_dir)).unwrap();
    let mut bmc_mock_handle = bmc_mock::CombinedServer::run(
        "bmc-mock",
        bmc_address_registry.clone(),
        Some(ListenerOrAddress::Listener(
            // let OS choose available port
            TcpListener::bind("127.0.0.1:0")?,
        )),
        server_config,
    );

    // For preingestion firmware checks to work, carbide needs a directory which exists to be
    // configured as the firmware_directory. It can be empty, because our mocks should be showing
    // the desired firmware verisions to carbide (and thus it won't try to update.) This folder will
    // be deleted on Drop.
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;

    // Begin the integration test by starting an API server. This will be shared between multiple
    // individual machine-a-tron-based tests, which can run in parallel against the same instance.
    let cancel_token = CancellationToken::new();
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
            cancel_token.clone(),
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
            cancel_token.clone(),
        )
        .await?,
    );

    let tenant_org_id = "tenant_organization";
    tenant::create(carbide_api_addrs, tenant_org_id, "Tenant Organization").await?;
    let tenant1_vpc = vpc::create(carbide_api_addrs, tenant_org_id).await?;
    let domain_id = domain::create(carbide_api_addrs, "tenant-1.local").await?;
    let managed_segment_id =
        subnet::create(carbide_api_addrs, &tenant1_vpc, &domain_id, 10, false).await?;

    // HostInband segments must live in a Flat VPC -- those VPC types are
    // mutually bound. Create one for the HostInband fixture.
    let flat_vpc = vpc::create_flat(carbide_api_addrs, tenant_org_id).await?;
    let host_inband_segment_id =
        subnet::create(carbide_api_addrs, &flat_vpc, &domain_id, 11, true).await?;

    // Create FNN VPC + VPC prefixes (IPv4 + IPv6) for dual-stack L3 linknet testing.
    let fnn_vpc = vpc::create_fnn(carbide_api_addrs, tenant_org_id).await?;
    let v4_vpc_prefix_id =
        vpc_prefix::create(carbide_api_addrs, &fnn_vpc, "10.10.12.0/24", "fnn-v4").await?;
    let v6_vpc_prefix_id =
        vpc_prefix::create(carbide_api_addrs, &fnn_vpc, "2001:db8:12::/48", "fnn-v6").await?;

    // Create dual-stack L2 segment on the FNN VPC for L2 dual-stack testing.
    let dual_stack_l2_segment_id =
        subnet::create_dual_stack(carbide_api_addrs, &fnn_vpc, &domain_id, 13).await?;

    // Run several tests in parallel.
    let all_tests = join_all([
        test_machine_a_tron_multidpu(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_multidpu(
            HostHardwareType::NvidiaDgxH100,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_multidpu(
            HostHardwareType::WiwynnGB200Nvl,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_multidpu(
            HostHardwareType::LenovoGB300Nvl,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_multidpu(
            HostHardwareType::NvidiaDgxGb300,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_multidpu(
            HostHardwareType::SupermicroGb300Nvl,
            &test_env,
            &bmc_address_registry,
            &managed_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_zerodpu(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            &flat_vpc,
        )
        .boxed(),
        test_machine_a_tron_nic_mode(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            &flat_vpc,
            &host_inband_segment_id,
        )
        .boxed(),
        test_machine_a_tron_nic_mode(
            HostHardwareType::HpeProliantDl380aGen11,
            &test_env,
            &bmc_address_registry,
            &flat_vpc,
            &host_inband_segment_id,
        )
        .boxed(),
        test_machine_a_tron_nic_mode(
            HostHardwareType::WiwynnGB200Nvl,
            &test_env,
            &bmc_address_registry,
            &flat_vpc,
            &host_inband_segment_id,
        )
        .boxed(),
        test_machine_a_tron_nic_mode(
            HostHardwareType::SupermicroGb300Nvl,
            &test_env,
            &bmc_address_registry,
            &flat_vpc,
            &host_inband_segment_id,
        )
        .boxed(),
        test_machine_a_tron_dpu_to_nic_mode_reregistration(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_dual_stack(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            &v4_vpc_prefix_id,
            &v6_vpc_prefix_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
        )
        .boxed(),
        test_machine_a_tron_dual_stack_l2(
            HostHardwareType::DellPowerEdgeR750,
            &test_env,
            &bmc_address_registry,
            &dual_stack_l2_segment_id,
            // Relay IP in admin net
            Ipv4Addr::new(172, 20, 0, 2),
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

    cancel_token.cancel();
    server_handle_1.wait().await?;
    server_handle_2.wait().await?;
    test_env.db_pool.close().await;
    bmc_mock_handle.stop().await?;
    Ok(())
}

/// Exercise the rack-aware machine-a-tron path independently from the other parallel scenarios.
#[tokio::test(flavor = "multi_thread")]
async fn test_machine_a_tron_rack_integration() -> eyre::Result<()> {
    let Some(test_env) = IntegrationTestEnvironment::try_from_environment(
        1,
        "api_server_test_machine_a_tron_rack_integration",
    )
    .await?
    else {
        return Ok(());
    };

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = test_env.root_dir.join("crates/bmc-mock");
    let server_config = bmc_mock::tls::server_config(Some(certs_dir)).unwrap();
    let mut bmc_mock_handle = bmc_mock::CombinedServer::run(
        "bmc-mock",
        bmc_address_registry.clone(),
        Some(ListenerOrAddress::Listener(TcpListener::bind(
            "127.0.0.1:0",
        )?)),
        server_config,
    );
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;
    let cancel_token = CancellationToken::new();
    let server_handle = utils::start_api_server(
        test_env.clone(),
        Some(HostPortPair::HostAndPort(
            "127.0.0.1".to_string(),
            bmc_mock_handle.address.port(),
        )),
        empty_firmware_dir.path().to_owned(),
        0,
        true,
        cancel_token.clone(),
    )
    .await?;

    test_machine_a_tron_rack(
        &test_env,
        &bmc_address_registry,
        Ipv4Addr::new(172, 20, 0, 2),
    )
    .await?;

    cancel_token.cancel();
    server_handle.wait().await?;
    test_env.db_pool.close().await;
    bmc_mock_handle.stop().await?;
    Ok(())
}

fn generate_core_metric_docs(metrics_endpoints: &[SocketAddr]) {
    let mut infos = metrics::collect_metric_infos(metrics_endpoints).unwrap();
    retain_existing_core_metric_infos(&mut infos);

    // Delete everything with "alt_metric_" prefix
    let mut infos: Vec<_> = infos
        .into_iter()
        .filter(|metric| !metric.name.starts_with("alt_metric"))
        .collect();

    // Sort metrics for consistency
    infos.sort_by(|e1, e2| e1.name.cmp(&e2.name));

    let mut docs = "# NVIDIA Infra Controller (NICo) Core Metrics\n\n".to_string();
    use std::fmt::Write;

    use askama_escape::Escaper;

    writeln!(
        &mut docs,
        "This file contains a list of metrics exported by NVIDIA Infra Controller (NICo). \
        The list is auto-generated from an integration test (`test_integration`). \
        Metrics for workflows which are not exercised by the test are missing. \
        NVLink partition monitor's metrics are documented in the manual: \
        [NVLink Partitioning](../manuals/nvlink_partitioning.md#metrics)."
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
    writeln!(&mut docs, "</table>").unwrap();

    let path = std::path::Path::new(METRIC_DOC_PATH);
    assert!(
        path.exists(),
        "Metric path at {} does not exist. Did the directory structure change?",
        path.to_str().unwrap()
    );

    std::fs::write(path, docs).unwrap();
}

fn retain_existing_core_metric_infos(infos: &mut Vec<metrics::MetricInfo>) {
    let mut infos_by_name = infos
        .drain(..)
        .map(|info| (info.name.clone(), info))
        .collect::<HashMap<_, _>>();

    for line in std::fs::read_to_string(METRIC_DOC_PATH)
        .unwrap_or_default()
        .lines()
    {
        if let Some(info) = metrics::MetricInfo::parse_from_docs_line(line) {
            infos_by_name.entry(info.name.clone()).or_insert(info);
        }
    }

    infos.extend(infos_by_name.into_values());
}

trait ParseFromHtmlDocs {
    fn parse_from_docs_line(line: &str) -> Option<Self>
    where
        Self: Sized;
}

impl ParseFromHtmlDocs for metrics::MetricInfo {
    fn parse_from_docs_line(line: &str) -> Option<Self> {
        let row = line.strip_prefix("<tr><td>")?.strip_suffix("</td></tr>")?;
        let cells = row.split("</td><td>").collect::<Vec<_>>();
        let [name, ty, help] = cells.as_slice() else {
            return None;
        };

        if *name == "Name" {
            return None;
        }

        let unescape_html_cell = |value: &str| -> String {
            if value.contains('&') {
                value
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&#39;", "'")
                    .replace("&quot;", "\"")
                    .replace("&amp;", "&")
            } else {
                value.to_string()
            }
        };

        Some(metrics::MetricInfo {
            name: unescape_html_cell(name),
            ty: unescape_html_cell(ty),
            help: unescape_html_cell(help),
        })
    }
}

pub(crate) const METRIC_DOC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/observability/core_metrics.md"
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
        credential_config: _,
        _vault_handle,
    } = test_env.clone();

    let bmc_address_registry = BmcMockRegistry::default();
    let certs_dir = PathBuf::from(format!("{}/crates/bmc-mock", test_env.root_dir.display()));
    let server_config = bmc_mock::tls::server_config(Some(certs_dir)).unwrap();
    let mut bmc_mock_handle = bmc_mock::CombinedServer::run(
        "bmc-mock",
        bmc_address_registry.clone(),
        Some(ListenerOrAddress::Listener(
            // let OS choose available port
            TcpListener::bind("127.0.0.1:0")?,
        )),
        server_config,
    );

    // For preingestion firmware checks to work, carbide needs a directory which exists to be
    // configured as the firmware_directory. It can be empty, because our mocks should be showing
    // the desired firmware verisions to carbide (and thus it won't try to update.) This folder will
    // be deleted on Drop.
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;

    // Begin the integration test by starting an API server. This will be shared between multiple
    // individual machine-a-tron-based tests, which can run in parallel against the same instance.
    let cancel_token = CancellationToken::new();
    let server_handle = utils::start_api_server(
        test_env.clone(),
        Some(HostPortPair::HostAndPort(
            "127.0.0.1".to_string(),
            bmc_mock_handle.address.port(),
        )),
        empty_firmware_dir.path().to_owned(),
        0,
        true,
        cancel_token.clone(),
    )
    .await?;

    // Before the initial host bootstrap, the dns_records view
    // should contain 0 entries.
    assert_eq!(0i64, get_dns_record_count(&db_pool).await);

    run_machine_a_tron_test(
        HostHardwareType::DellPowerEdgeR750,
        1,
        1,
        false,
        None,
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

                let tenant_org_id = "tenant_organization";
                tenant::create(&carbide_api_addrs, tenant_org_id, "Tenant Organization").await?;
                let vpc_id = vpc::create(&carbide_api_addrs, tenant_org_id).await?;
                let domain_id = domain::create(&carbide_api_addrs, "tenant-1.local").await?;
                let segment_id = subnet::create(&carbide_api_addrs, &vpc_id, &domain_id, 10, false).await?;
                let host_machine_id = machine_handle.observed_machine_id().expect("Should have gotten a machine ID by now");

                // Create instance with phone_home enabled
                let instance_id = instance::create(
                    &carbide_api_addrs,
                    &host_machine_id,
                    &segment_id,
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
    cancel_token.cancel();
    server_handle.wait().await?;
    db_pool.close().await;
    Ok(())
}

async fn test_machine_a_tron_multidpu(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    segment_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        2,
        false,
        None,
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
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready, allocating instance",
                );
                let instance_id = instance::create(
                    carbide_api_addrs,
                    &machine_id,
                    &segment_id,
                    None,
                    false,
                    false,
                    &[],
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Assigned/Ready", Duration::from_secs(90))
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
                    machine_id = %machine_id,
                    "Machine has made it to Assigned/Ready, releasing instance",
                );
                instance::release(carbide_api_addrs, &machine_id, &instance_id, false).await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready again, all done",
                );
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

#[derive(Clone)]
struct TestRackConfig {
    rack_id: RackId,
    rack_profile_id: RackProfileId,
}

async fn test_machine_a_tron_rack(
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    let rack_id = RackId::new("machine-a-tron-nvl72");
    run_machine_a_tron_test(
        HostHardwareType::WiwynnGB200Nvl,
        18,
        2,
        false,
        Some(TestRackConfig {
            rack_id: rack_id.clone(),
            rack_profile_id: RackProfileId::new("NVL72"),
        }),
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            let db_pool = test_env.db_pool.clone();
            let rack_id = rack_id.clone();
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(240))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready")
                    .to_string();

                let managed_rack_id: Option<String> =
                    sqlx::query_scalar("SELECT rack_id FROM machines WHERE id = $1")
                        .bind(machine_id)
                        .fetch_one(&db_pool)
                        .await?;
                assert_eq!(managed_rack_id.as_deref(), Some(rack_id.as_str()));

                let expected_machine_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM expected_machines WHERE rack_id = $1")
                        .bind(rack_id.as_str())
                        .fetch_one(&db_pool)
                        .await?;
                assert_eq!(expected_machine_count, 18);

                let rack_profile_id: String = sqlx::query_scalar(
                    "SELECT rack_profile_id FROM expected_racks WHERE rack_id = $1",
                )
                .bind(rack_id.as_str())
                .fetch_one(&db_pool)
                .await?;
                assert_eq!(rack_profile_id, "NVL72");

                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_zerodpu(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    flat_vpc_id: &str,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        0,
        false,
        None,
        test_env,
        bmc_mock_registry,
        Ipv4Addr::new(172, 20, 0, 2),
        |machine_handle| {
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            let flat_vpc_id = flat_vpc_id.to_string();
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready, allocating instance",
                );

                let instance_id = instance::create_with_auto_host_inband_networking(
                    carbide_api_addrs,
                    &machine_id,
                    &flat_vpc_id,
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Assigned/Ready", Duration::from_secs(90))
                    .await?;
                assert_auto_instance_network(carbide_api_addrs, &instance_id, &flat_vpc_id).await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Assigned/Ready, releasing instance",
                );

                instance::release(carbide_api_addrs, &machine_id, &instance_id, false).await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready again, all done",
                );
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_nic_mode(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    flat_vpc_id: &str,
    host_inband_segment_id: &str,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        1,
        true,
        None,
        test_env,
        bmc_mock_registry,
        Ipv4Addr::new(172, 20, 0, 2),
        |machine_handle| {
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            let flat_vpc_id = flat_vpc_id.to_string();
            let host_inband_segment_id = host_inband_segment_id.to_string();
            let expected_host_mac = machine_handle
                .host_info()
                .dpus
                .first()
                .expect("NIC-mode host should contain at least one DPU NIC")
                .host_mac_address
                .to_string();
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready, allocating instance",
                );

                assert_nic_mode_host(
                    carbide_api_addrs,
                    &machine_id,
                    &expected_host_mac,
                    &host_inband_segment_id,
                )
                .await?;

                let instance_id = instance::create_with_auto_host_inband_networking(
                    carbide_api_addrs,
                    &machine_id,
                    &flat_vpc_id,
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Assigned/Ready", Duration::from_secs(90))
                    .await?;
                assert_auto_instance_network(carbide_api_addrs, &instance_id, &flat_vpc_id).await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Assigned/Ready, releasing instance",
                );

                instance::release(carbide_api_addrs, &machine_id, &instance_id, false).await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine has made it to Ready again, all done",
                );
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn assert_nic_mode_host(
    carbide_api_addrs: &[SocketAddr],
    machine_id: &carbide_uuid::machine::MachineId,
    expected_host_mac: &str,
    host_inband_segment_id: &str,
) -> eyre::Result<()> {
    let machine = machine::get_json_by_id(carbide_api_addrs, machine_id).await?;
    let associated_dpus = machine["associatedDpuMachineIds"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    eyre::ensure!(
        associated_dpus.is_empty(),
        "NIC-mode host {machine_id} still has associated DPUs: {associated_dpus:?}"
    );

    let interfaces = machine["interfaces"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("NIC-mode host {machine_id} has no interfaces"))?;
    eyre::ensure!(
        interfaces
            .iter()
            .all(|interface| interface["attachedDpuMachineId"].is_null()),
        "NIC-mode host {machine_id} still has a DPU-backed interface: {interfaces:?}"
    );

    let has_expected_primary_host_inband_interface = interfaces.iter().any(|interface| {
        interface["macAddress"]
            .as_str()
            .is_some_and(|mac| mac.eq_ignore_ascii_case(expected_host_mac))
            && interface["primaryInterface"] == true
            && interface["segmentId"]["value"] == host_inband_segment_id
            && interface["interfaceType"] != "INTERFACE_TYPE_BMC"
    });
    eyre::ensure!(
        has_expected_primary_host_inband_interface,
        "NIC-mode host {machine_id} did not promote DPU host-facing PF {expected_host_mac} as its primary HostInband interface"
    );
    Ok(())
}

async fn assert_auto_instance_network(
    carbide_api_addrs: &[SocketAddr],
    instance_id: &str,
    flat_vpc_id: &str,
) -> eyre::Result<()> {
    let instance = instance::get_instance_json_by_id(carbide_api_addrs, instance_id).await?;
    let network = &instance["config"]["network"];
    eyre::ensure!(
        network["auto"] == true,
        "instance {instance_id} did not retain auto networking: {network}"
    );
    eyre::ensure!(
        network["interfaces"].as_array().is_some_and(Vec::is_empty),
        "instance {instance_id} exposed resolved interfaces in its external config: {network}"
    );
    eyre::ensure!(
        network["autoConfig"]["vpcId"]["value"] == flat_vpc_id,
        "instance {instance_id} did not retain flat VPC {flat_vpc_id}: {network}"
    );

    let status_interfaces = instance["status"]["network"]["interfaces"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("instance {instance_id} has no network status interfaces"))?;
    eyre::ensure!(
        !status_interfaces.is_empty()
            && status_interfaces.iter().all(|interface| {
                interface["vpcId"]["value"] == flat_vpc_id
                    && interface["macAddress"]
                        .as_str()
                        .is_some_and(|mac| !mac.is_empty())
                    && interface["addresses"]
                        .as_array()
                        .is_some_and(|values| !values.is_empty())
                    && interface["gateways"]
                        .as_array()
                        .is_some_and(|values| !values.is_empty())
                    && interface["prefixes"]
                        .as_array()
                        .is_some_and(|values| !values.is_empty())
            }),
        "instance {instance_id} status does not contain resolved flat VPC networking: {status_interfaces:?}"
    );
    eyre::ensure!(
        instance["status"]["network"]["configsSynced"] == "SYNCED",
        "instance {instance_id} network status is not synced: {}",
        instance["status"]["network"]
    );
    Ok(())
}

/// DPU-mode -> NIC-mode flip + zero-DPU re-ingestion (machine-a-tron harness,
/// #2661 / #2632). A host boots as a managed-DPU machine, an operator declares
/// NIC mode and force-deletes it with `--delete-interfaces`, and the host
/// re-ingests with no managed DPUs -- exercising the simulated BlueField flip
/// (`Mode.Set` staged, applied on power-cycle), the host converging off its DPU
/// DHCP relay and dropping the DPU from its inventory, and site-explorer
/// re-registering the host with zero managed DPUs.
///
/// Asserts the re-ingest milestone directly against the database -- the host's
/// (stable, TPM-derived) machine row returns with its data-plane NIC and no
/// managed DPU -- then drives the re-ingested NIC-mode host all the way to Ready.
async fn test_machine_a_tron_dpu_to_nic_mode_reregistration(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        1,
        // Start in DPU mode: the host comes up as a managed-DPU machine, and we
        // flip it to NIC mode below.
        false,
        None,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            async move {
                // 1. Host reaches Ready as a managed-DPU machine.
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let bmc_mac = machine_handle.host_info().bmc_mac_address.to_string();
                let initial_machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!(
                    initial_machine_id = %initial_machine_id,
                    bmc_mac_address = %bmc_mac,
                    "Machine is Ready in DPU mode; flipping to NIC mode",
                );

                // 2. Flip the ExpectedMachine to NIC mode. Get the current record,
                //    set `dpu_mode`, and round-trip the full message back through
                //    UpdateExpectedMachine (the same get-mutate-update the admin CLI
                //    `patch_expected_machine` uses, so we preserve every other field).
                let get_req = serde_json::json!({ "bmc_mac_address": bmc_mac });
                let expected_machine_json =
                    api_test_helper::grpcurl::grpcurl(carbide_api_addrs, "GetExpectedMachine", Some(&get_req))
                        .await?;
                let mut expected_machine: serde_json::Value =
                    serde_json::from_str(&expected_machine_json)?;
                expected_machine["dpu_mode"] = serde_json::json!("NIC_MODE");
                api_test_helper::grpcurl::grpcurl(
                    carbide_api_addrs,
                    "UpdateExpectedMachine",
                    Some(&expected_machine),
                )
                .await?;
                tracing::info!(
                    bmc_mac_address = %bmc_mac,
                    "ExpectedMachine for now declares NIC mode",
                );

                // 3. Force-delete the managed-DPU machine so site-explorer
                //    re-ingests the host under the new declared mode. This is the
                //    issue's `force-delete --delete-interfaces`: it removes the host
                //    + DPU machine rows, their interfaces, and their explored-endpoint
                //    records, so site-explorer rediscovers and re-ingests from scratch.
                //
                //    Query by the host's MachineId: `host_query` resolves a
                //    data-plane MAC or a machine id, but not a BMC MAC
                //    (`find_by_mac_address` excludes BMC interfaces), so the BMC MAC
                //    used for the ExpectedMachine lookups above would not match here.
                let force_delete_req = serde_json::json!({
                    "host_query": initial_machine_id,
                    "delete_interfaces": true,
                });
                api_test_helper::grpcurl::grpcurl(
                    carbide_api_addrs,
                    "AdminForceDeleteMachine",
                    Some(&force_delete_req),
                )
                .await?;
                tracing::info!(
                    initial_machine_id = %initial_machine_id,
                    "Force-deleted machine; awaiting re-ingestion as NicMode",
                );

                // 4. Wait for the host to re-ingest as a zero-managed-DPU machine,
                //    asserted directly against the database. The host's TPM-derived
                //    MachineId is deterministic (a hash of its EK cert), so the
                //    re-ingested host resurrects under the SAME id captured before
                //    the flip -- the machine-a-tron handle's observed id is cleared
                //    by the force-delete, so we key off the captured id. First
                //    confirm the re-ingest milestone (the host row is back with its
                //    NIC and no managed DPU); step 5 then drives it all the way to
                //    Ready. Allow generous time for the rate-limited flip
                //    power-cycle plus full rediscovery.
                let host_id = initial_machine_id.to_string();
                let pool = &test_env.db_pool;
                let reingest_deadline = time::Instant::now() + Duration::from_secs(180);
                loop {
                    // The host row is back under its stable TPM-derived id.
                    let host_exists: bool =
                        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machines WHERE id = $1)")
                            .bind(&host_id)
                            .fetch_one(pool)
                            .await?;
                    // It re-ingested with at least one data-plane (non-BMC) NIC.
                    let nic_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM machine_interfaces \
                         WHERE machine_id = $1 AND interface_type != 'Bmc'",
                    )
                    .bind(&host_id)
                    .fetch_one(pool)
                    .await?;
                    // Zero managed DPUs: no data-plane interface still points at a
                    // DPU (any non-null `attached_dpu_machine_id`), so the BlueField
                    // flipped to NIC mode and is no longer managed. Count attachments
                    // directly instead of joining `machines`, so a stale attachment
                    // pointing at an already-deleted DPU row still counts.
                    let managed_dpu_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM machine_interfaces \
                         WHERE machine_id = $1 \
                         AND interface_type != 'Bmc' \
                         AND attached_dpu_machine_id IS NOT NULL",
                    )
                    .bind(&host_id)
                    .fetch_one(pool)
                    .await?;

                    if host_exists && nic_count >= 1 && managed_dpu_count == 0 {
                        tracing::info!(
                            host_machine_id = %host_id,
                            nic_interface_count = nic_count,
                            "Host re-ingested as a zero-managed-DPU machine; DPU-to-NIC flip applied",
                        );
                        break;
                    }
                    if time::Instant::now() >= reingest_deadline {
                        panic!(
                            "host {host_id} did not re-ingest as a zero-managed-DPU NicMode machine \
                             within the timeout (host_exists={host_exists}, nic_count={nic_count}, \
                             managed_dpu_count={managed_dpu_count})"
                        );
                    }
                    sleep(Duration::from_secs(2)).await;
                }

                // 5. Drive the re-ingested NicMode host all the way to Ready --
                //    the host BMC now serves an event log so the controller's
                //    restart verification can confirm reboots, and the zero-DPU
                //    lockdown short-circuit lets it skip the DPU-down wait.
                tracing::info!(
                    host_machine_id = %host_id,
                    "Waiting for re-ingested NicMode host to reach Ready",
                );
                let ready_deadline = time::Instant::now() + Duration::from_secs(240);
                loop {
                    let resp = api_test_helper::grpcurl::grpcurl(
                        carbide_api_addrs,
                        "FindMachinesByIds",
                        Some(&serde_json::json!({ "machine_ids": [{"id": host_id}] })),
                    )
                    .await?;
                    let resp: serde_json::Value = serde_json::from_str(&resp)?;
                    let state = resp["machines"][0]["state"].as_str().unwrap_or("");
                    if state == "Ready" {
                        tracing::info!(
                            host_machine_id = %host_id,
                            machine_state = state,
                            "Re-ingested NicMode host reached Ready",
                        );
                        break;
                    }
                    if time::Instant::now() >= ready_deadline {
                        panic!(
                            "re-ingested NicMode host {host_id} did not reach Ready within the timeout (last state: {state})"
                        );
                    }
                    sleep(Duration::from_secs(2)).await;
                }
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

async fn test_machine_a_tron_dual_stack(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    v4_vpc_prefix_id: &str,
    v6_vpc_prefix_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        1,
        false,
        None,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            let v4_prefix_id = v4_vpc_prefix_id.to_string();
            let v6_prefix_id = v6_vpc_prefix_id.to_string();
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine is Ready, allocating dual-stack instance via ipv6 config",
                );
                let instance_id = instance::create_with_vpc_prefixes(
                    carbide_api_addrs,
                    &machine_id,
                    &[&v4_prefix_id, &v6_prefix_id],
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state(
                        "Assigned/Ready",
                        Duration::from_secs(90),
                    )
                    .await?;

                // Wait for the agent to report interface addresses. The agent runs
                // a network observation loop that populates addresses asynchronously
                // after the instance reaches Assigned/Ready.
                let machine_id_str = machine_id.to_string();
                let mut addrs = vec![];
                for _ in 0..30 {
                    let instance_json = instance::get_instance_json_by_machine_id(
                        carbide_api_addrs,
                        &machine_id_str,
                    )
                    .await?;
                    if let Some(iface) = instance_json["instances"][0]["status"]["network"]["interfaces"]
                        .as_array()
                        .and_then(|ifaces| ifaces.first())
                        && let Some(a) = iface["addresses"].as_array()
                        && !a.is_empty()
                    {
                        addrs = a.clone();
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                let addr_strings: Vec<&str> =
                    addrs.iter().filter_map(|a| a.as_str()).collect();
                let has_ipv4 = addr_strings.iter().any(|a| a.contains('.'));
                let has_ipv6 = addr_strings.iter().any(|a| a.contains(':'));
                assert!(
                    has_ipv4,
                    "Dual-stack interface should have an IPv4 address, got: {addr_strings:?}"
                );
                assert!(
                    has_ipv6,
                    "Dual-stack interface should have an IPv6 address, got: {addr_strings:?}"
                );
                assert_eq!(
                    addr_strings.len(),
                    2,
                    "Dual-stack interface should have exactly 2 addresses (IPv4 + IPv6), got: {addr_strings:?}"
                );

                tracing::info!(
                    machine_id = %machine_id,
                    addresses = ?addr_strings,
                    "Machine dual-stack allocation verified",
                );

                instance::release(carbide_api_addrs, &machine_id, &instance_id, false)
                    .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine back to Ready after dual-stack release",
                );
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

/// Tests dual-stack on an FNN L2 segment (shared subnet with SVI/VRR).
/// The segment is pre-created with both IPv4 and IPv6 prefixes, and the
/// handler allocates SVI IPs for both. Instances get one IP per prefix.
async fn test_machine_a_tron_dual_stack_l2(
    hw_type: HostHardwareType,
    test_env: &IntegrationTestEnvironment,
    bmc_mock_registry: &BmcMockRegistry,
    dual_stack_segment_id: &str,
    admin_dhcp_relay_address: Ipv4Addr,
) -> eyre::Result<()> {
    run_machine_a_tron_test(
        hw_type,
        1,
        1,
        false,
        None,
        test_env,
        bmc_mock_registry,
        admin_dhcp_relay_address,
        |machine_handle| {
            let segment_id = dual_stack_segment_id.to_string();
            let carbide_api_addrs = &test_env.carbide_api_addrs;
            async move {
                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                let machine_id = machine_handle
                    .observed_machine_id()
                    .expect("Machine ID should be set if host is ready");
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine is Ready, allocating dual-stack L2 instance",
                );
                let instance_id = instance::create(
                    carbide_api_addrs,
                    &machine_id,
                    &segment_id,
                    None,
                    false,
                    false,
                    &[],
                )
                .await?;

                machine_handle
                    .wait_until_machine_up_with_api_state(
                        "Assigned/Ready",
                        Duration::from_secs(120),
                    )
                    .await?;

                tracing::info!(
                    machine_id = %machine_id,
                    "Machine dual-stack L2 instance allocated and reached Assigned/Ready",
                );

                instance::release(carbide_api_addrs, &machine_id, &instance_id, false).await?;

                machine_handle
                    .wait_until_machine_up_with_api_state("Ready", Duration::from_secs(90))
                    .await?;
                tracing::info!(
                    machine_id = %machine_id,
                    "Machine back to Ready after dual-stack L2 release",
                );
                Ok::<(), eyre::Report>(())
            }
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_machine_a_tron_test<F, O>(
    hw_type: HostHardwareType,
    host_count: u32,
    dpu_per_host_count: u32,
    dpus_in_nic_mode: bool,
    rack: Option<TestRackConfig>,
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
        .context("no carbide API addresses configured")?;
    let additional_api_urls = test_env.carbide_api_addrs[1..]
        .iter()
        .map(|a| format!("https://{}:{}", a.ip(), a.port()))
        .collect();
    let (racks, rack_id) = rack
        .map(|rack| {
            let rack_id = rack.rack_id;
            (
                BTreeMap::from([(
                    rack_id.clone(),
                    RackConfig {
                        rack_profile_id: rack.rack_profile_id,
                    },
                )]),
                Some(rack_id),
            )
        })
        .unwrap_or_default();
    let mat_config = MachineATronConfig {
        racks,
        machines: BTreeMap::from([(
            "config".to_string(),
            Arc::new(MachineConfig {
                rack_id,
                hw_type,
                host_count,
                dpu_per_host_count,
                dpu_reboot_delay: 1,
                host_reboot_delay: 1,
                template_dir: test_env
                    .root_dir
                    .join("crates/machine-a-tron/templates")
                    .to_str()
                    .unwrap()
                    .to_string(),
                admin_dhcp_relay_address,
                // Keep this distinct from the Admin relay so NIC-mode tests
                // fail if machine-a-tron sends host DHCP through Admin.
                host_inband_dhcp_relay_address: Some(Ipv4Addr::new(10, 10, 11, 2)),
                oob_dhcp_relay_address: Ipv4Addr::new(172, 20, 1, 1),
                vpc_count: 0,
                subnets_per_vpc: 0,
                run_interval_idle: Duration::from_secs(1),
                run_interval_working: Duration::from_millis(100),
                network_status_run_interval: Duration::from_secs(1),
                scout_run_interval: Duration::from_secs(1),
                network_virtualization_type: None,
                dpus_in_nic_mode,
                dpu_firmware_versions: None,
                dpu_agent_version: None,
            }),
        )]),
        carbide_api_url: format!("https://{}:{}", api_addr.ip(), api_addr.port()),
        log_file: None,
        bmc_mock_port: 0, // unused, we're using dynamic ports on localhost
        bmc_mock_certs_dir: None,
        interface: String::from("UNUSED"), // unused, we're using dynamic ports on localhost
        tui_enabled: false,
        use_single_bmc_mock: false, // unused, we're constructing machines ourselves
        configure_carbide_bmc_proxy_host: None,
        persist_dir: None,
        cleanup_on_quit: false,
        register_expected_machines: true,
        host_bmc_password: None,
        dpu_bmc_password: None,
        api_refresh_interval: Duration::from_millis(500),
        mock_bmc_ssh_server: false,
        mock_bmc_ssh_port: None,
        enable_ipmi_simulation: false,
        hw_mac_address_ranges: None,
        mac_address_pool: None,
    };

    let (machine_handles, _mat_handle) = api_test_helper::machine_a_tron::run_local(
        mat_config,
        additional_api_urls,
        &test_env.root_dir,
        Some(bmc_mock_registry.clone()),
        TEST_MAC_POOL.clone(),
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
