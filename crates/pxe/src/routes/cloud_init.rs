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

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum_template::TemplateEngine;
use base64::Engine as _;
use carbide_host_support::agent_config;
use carbide_host_support::bootstrap_ca::BootstrapCaSource;
use carbide_instrument::emit;
use carbide_uuid::machine::MachineInterfaceId;
use rpc::forge;
use rpc::forge::PxeDomain;

use crate::common::{AppState, Machine};
use crate::metrics::{BootEndpoint, OutcomeReason, PxeBootOutcome, PxeCloudInitRequestFailed};

const DEFAULT_NUM_OF_VFS: u32 = 16;
const DEFAULT_HBN_BRIDGE: &str = "br-hbn";

fn parse_bootstrap_ca_source(value: i32) -> Result<BootstrapCaSource, String> {
    forge::BootstrapCaSource::try_from(value)
        .map(BootstrapCaSource::from)
        .map_err(|_| format!("unknown bootstrap CA source value {value}"))
}

/// Generates the content of the /etc/forge/config.toml file.
///
/// When `api_url_override` is provided (for external hosts on the
/// static-assignments segment), it's written into the `[forge-system]`
/// section so the DPU agent connects to the correct API endpoint
/// instead of defaulting to `carbide-api.forge`.
fn generate_forge_agent_config(
    machine_interface_id: MachineInterfaceId,
    api_url_override: Option<&str>,
) -> String {
    let config = agent_config::AgentConfigFromPxe {
        forge_system: api_url_override.map(|url| agent_config::ForgeSystemConfigFromPxe {
            api_server: url.to_string(),
        }),
        machine: agent_config::MachineConfigFromPxe {
            interface_id: machine_interface_id,
        },
    };

    toml::to_string(&config).unwrap_or_else(|e| format!("# serialization error: {e}"))
}

/// The generic-failure funnel for the cloud-init routes: whatever data was
/// missing, the client receives the same generic error template, and the
/// caller says which missing data it was -- the reason label carries the
/// per-site truth while the response stays generic.
fn log_and_generate_generic_error(
    error: String,
    reason: OutcomeReason,
) -> (String, HashMap<String, String>) {
    emit(PxeCloudInitRequestFailed {
        endpoint: BootEndpoint::CloudInit,
        reason,
        error,
    });
    let mut template_data: HashMap<String, String> = HashMap::new();
    template_data.insert(
        "error".to_string(),
        "An error occurred while rendering the request".to_string(),
    );
    ("error".to_string(), template_data) // Send a generic error back
}

#[allow(clippy::too_many_arguments)]
fn user_data_handler(
    machine_interface_id: MachineInterfaceId,
    machine_interface: forge::MachineInterface,
    domain: PxeDomain,
    hbn_reps: Option<String>,
    num_of_vfs: Option<u32>,
    host_representor_intercept_bridging: Option<String>,
    hbn_bridge: Option<String>,
    api_url_override: Option<String>,
    pxe_url_override: Option<String>,
    bootstrap_ca_source: BootstrapCaSource,
    state: State<AppState>,
) -> (String, HashMap<String, String>) {
    let config = state.runtime_config.clone();
    let forge_agent_config =
        generate_forge_agent_config(machine_interface_id, api_url_override.as_deref());

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine_interface.mac_address);

    if let Some(domain_oneof) = domain.domain {
        let domain_name = match domain_oneof {
            forge::pxe_domain::Domain::LegacyDomain(domain) => domain.name,
            forge::pxe_domain::Domain::NewDomain(domain) => domain.name,
        };
        context.insert(
            "hostname".to_string(),
            format!("{}.{}", machine_interface.hostname, domain_name),
        );
    }
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert(
        "api_url".to_string(),
        api_url_override.unwrap_or(config.client_facing_api_url),
    );
    context.insert(
        "pxe_url".to_string(),
        pxe_url_override.unwrap_or(config.pxe_url),
    );
    context.insert(
        "forge_agent_config_b64".to_string(),
        base64::engine::general_purpose::STANDARD.encode(forge_agent_config),
    );
    context.insert(
        "bootstrap_ca_source".to_string(),
        bootstrap_ca_source.to_string(),
    );

    let bmc_fw_update = state
        .engine
        .render("bmc_fw_update", HashMap::<String, String>::new())
        .unwrap_or("".to_string());
    context.insert("forge_bmc_fw_update".to_string(), bmc_fw_update);

    let seconds_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();

    context.insert(
        "seconds_since_epoch".to_string(),
        seconds_since_epoch.to_string(),
    );

    if let Some(hbn_reps) = hbn_reps {
        context.insert("forge_hbn_reps".to_string(), hbn_reps);
    }

    let num_of_vfs = num_of_vfs.unwrap_or(DEFAULT_NUM_OF_VFS);
    context.insert("num_of_vfs".to_string(), num_of_vfs.to_string());
    context.insert(
        "forge_hbn_bridge".to_string(),
        hbn_bridge.unwrap_or_else(|| DEFAULT_HBN_BRIDGE.to_string()),
    );

    if let Some(host_representor_intercept_bridging) = host_representor_intercept_bridging {
        context.insert(
            "forge_host_representor_intercept_bridging".to_string(),
            host_representor_intercept_bridging,
        );
    }

    ("user-data".to_string(), context)
}

async fn user_data(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let (template_key, template_data) = match (
        machine.instructions.custom_cloud_init,
        machine.instructions.discovery_instructions,
    ) {
        (Some(custom_cloud_init), _) => {
            let mut template_data: HashMap<String, String> = HashMap::new();
            template_data.insert("user_data".to_string(), custom_cloud_init);
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::CloudInit,
                reason: OutcomeReason::Ok,
            });
            ("user-data-assigned".to_string(), template_data)
        }
        (None, Some(discovery_instructions)) => {
            match (
                discovery_instructions.machine_interface,
                discovery_instructions.domain,
            ) {
                (Some(interface), Some(domain)) => match interface.id {
                    Some(machine_interface_id) => {
                        match parse_bootstrap_ca_source(discovery_instructions.bootstrap_ca_source)
                        {
                            Ok(bootstrap_ca_source) => {
                                emit(PxeBootOutcome {
                                    endpoint: BootEndpoint::CloudInit,
                                    reason: OutcomeReason::Ok,
                                });
                                user_data_handler(
                                    machine_interface_id,
                                    interface,
                                    domain,
                                    discovery_instructions.hbn_reps,
                                    discovery_instructions.num_of_vfs,
                                    discovery_instructions.host_representor_intercept_bridging,
                                    discovery_instructions.hbn_bridge,
                                    machine.instructions.api_url_override,
                                    machine.instructions.pxe_url_override,
                                    bootstrap_ca_source,
                                    state.clone(),
                                )
                            }
                            Err(error) => log_and_generate_generic_error(
                                error,
                                OutcomeReason::InstructionsInvalid,
                            ),
                        }
                    }
                    None => log_and_generate_generic_error(
                        format!("The interface ID should not be null: {interface:?}"),
                        OutcomeReason::InterfaceNotFound,
                    ),
                },
                (interface, domain) => log_and_generate_generic_error(
                    format!("The interface and domain were not found: {interface:?}, {domain:?}"),
                    OutcomeReason::InterfaceNotFound,
                ),
            }
        }
        (None, None) => {
            let mut template_data: HashMap<String, String> = HashMap::new();
            template_data.insert("user_data".to_string(), "{}".to_string());
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::CloudInit,
                reason: OutcomeReason::Ok,
            });
            ("user-data-assigned".to_string(), template_data)
        }
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

async fn meta_data(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let (template_key, template_data) = match machine.instructions.metadata {
        None => log_and_generate_generic_error(
            format!("No metadata was found for machine {machine:?}"),
            OutcomeReason::MetadataNotFound,
        ),
        Some(metadata) => {
            let mut template_data = HashMap::from([
                ("instance_id".to_string(), metadata.instance_id),
                ("cloud_name".to_string(), metadata.cloud_name),
                ("platform".to_string(), metadata.platform),
            ]);
            if !metadata.local_hostname.is_empty() {
                template_data.insert("local_hostname".to_string(), metadata.local_hostname);
            }

            emit(PxeBootOutcome {
                endpoint: BootEndpoint::CloudInit,
                reason: OutcomeReason::Ok,
            });
            ("meta-data".to_string(), template_data)
        }
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

/// Extracts the top-level `network:` key (if present) from a tenant's
/// custom cloud-init document and returns it as its own standalone YAML
/// document, suitable for seeding NoCloud's separate `network-config`
/// file. A `network:` key inside `user-data` itself is not a recognized
/// user-data format and is silently ignored by cloud-init.
fn extract_network_config(custom_cloud_init: &str) -> Option<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(custom_cloud_init).ok()?;
    serde_yaml::to_string(value.get("network")?).ok()
}

/// Default network-config served when a tenant hasn't provided a custom
/// `network:` key in their cloud-init userdata. cloud-init's own default
/// behavior (no network-config at all) only DHCPs the first network
/// interface it finds; this instead DHCPs every matching interface, under
/// both the predictable ("en*") and legacy ("eth*") naming conventions,
/// so multi-NIC hosts come up with working networking on every port.
const DEFAULT_NETWORK_CONFIG: &str = r#"version: 2
ethernets:
  predictable-names:
    match:
      name: "en*"
    dhcp4: true
    dhcp6: true
  legacy-names:
    match:
      name: "eth*"
    dhcp4: true
    dhcp6: true
"#;

/// Resolves the network-config YAML to use for a machine: the `network:`
/// key extracted from the tenant's custom cloud-init userdata if present,
/// otherwise DEFAULT_NETWORK_CONFIG (DHCP on every interface), rather
/// than an empty document that would fall back to cloud-init's own
/// first-interface-only default.
fn resolve_network_config(custom_cloud_init: Option<&str>) -> Cow<'static, str> {
    custom_cloud_init
        .and_then(extract_network_config)
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed(DEFAULT_NETWORK_CONFIG))
}

/// Serves NoCloud's `network-config` document for a tenant's assigned
/// machine, extracted from any `network:` key present in their custom
/// cloud-init userdata. When no such key is present, serves
/// DEFAULT_NETWORK_CONFIG instead of an empty document, so hosts get
/// DHCP on every interface by default rather than cloud-init's own
/// first-interface-only behavior.
async fn network_config(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let network_config_yaml =
        resolve_network_config(machine.instructions.custom_cloud_init.as_deref());
    let template_data = HashMap::from([("network_config", network_config_yaml)]);
    axum_template::Render("network-config", state.engine.clone(), template_data)
}

async fn vendor_data(state: State<AppState>) -> impl IntoResponse {
    emit(PxeBootOutcome {
        endpoint: BootEndpoint::CloudInit,
        reason: OutcomeReason::Ok,
    });
    axum_template::Render(
        "printcontext",
        state.engine.clone(),
        HashMap::<String, String>::new(),
    )
}

/// Builds the PXE service's route table for the cloud-init-related
/// endpoints served under `path_prefix`: `user-data`, `meta-data`,
/// `vendor-data`, and `network-config`.
pub(crate) fn get_router(path_prefix: &str) -> Router<AppState> {
    Router::new()
        .route(
            format!("{}/{}", path_prefix, "user-data").as_str(),
            get(user_data),
        )
        .route(
            format!("{}/{}", path_prefix, "meta-data").as_str(),
            get(meta_data),
        )
        .route(
            format!("{}/{}", path_prefix, "vendor-data").as_str(),
            get(vendor_data),
        )
        .route(
            format!("{}/{}", path_prefix, "network-config").as_str(),
            get(network_config),
        )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use carbide_instrument::testing::MetricsCapture;
    use carbide_test_support::{Check, check_values};

    use super::*;
    use crate::common::test_app_state;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/test_data");

    fn render_user_data_for_bootstrap_ca(source: BootstrapCaSource) -> String {
        let template_glob = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/templates/**/*");
        let tera = tera::Tera::new(template_glob).unwrap();
        let context = HashMap::from([
            ("bootstrap_ca_source".to_string(), source.to_string()),
            (
                "api_url".to_string(),
                "https://carbide-api.forge".to_string(),
            ),
            (
                "forge_agent_config_b64".to_string(),
                "W21hY2hpbmVdCg==".to_string(),
            ),
            ("forge_bmc_fw_update".to_string(), String::new()),
            ("forge_hbn_reps".to_string(), String::new()),
            ("forge_hbn_bridge".to_string(), "br-hbn".to_string()),
            ("hostname".to_string(), "test-host".to_string()),
            (
                "interface_id".to_string(),
                "91609f10-c91d-470d-a260-6293ea0c1234".to_string(),
            ),
            ("num_of_vfs".to_string(), "3".to_string()),
            (
                "pxe_url".to_string(),
                "http://carbide-pxe.forge".to_string(),
            ),
            ("seconds_since_epoch".to_string(), "0".to_string()),
        ]);

        tera.render(
            "user-data",
            &tera::Context::from_serialize(context).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_ca_source_protobuf_values_fail_closed() {
        check_values(
            [
                Check {
                    scenario: "legacy download preserves historical command without local validation",
                    input: forge::BootstrapCaSource::LegacyDownload as i32,
                    expect: Ok(BootstrapCaSource::LegacyDownload),
                },
                Check {
                    scenario: "embedded",
                    input: forge::BootstrapCaSource::Embedded as i32,
                    expect: Ok(BootstrapCaSource::Embedded),
                },
                Check {
                    scenario: "mounted",
                    input: forge::BootstrapCaSource::Mounted as i32,
                    expect: Ok(BootstrapCaSource::Mounted),
                },
                Check {
                    scenario: "unknown",
                    input: 99,
                    expect: Err("unknown bootstrap CA source value 99".to_string()),
                },
            ],
            parse_bootstrap_ca_source,
        );
    }

    #[test]
    fn user_data_template_applies_bootstrap_ca_policy() {
        check_values(
            [
                Check {
                    scenario: "legacy download",
                    input: BootstrapCaSource::LegacyDownload,
                    expect: (1, false, false, false, false),
                },
                Check {
                    scenario: "embedded",
                    input: BootstrapCaSource::Embedded,
                    expect: (0, true, true, false, true),
                },
                Check {
                    scenario: "mounted",
                    input: BootstrapCaSource::Mounted,
                    expect: (0, true, false, true, false),
                },
            ],
            |source| {
                let rendered = render_user_data_for_bootstrap_ca(source);
                (
                    rendered.matches("ip vrf exec mgmt curl --retry 5 --retry-all-errors -v -o /opt/forge/forge_root.pem http://carbide-pxe.forge/api/v0/tls/root_ca").count(),
                    rendered.contains("validate_bootstrap_ca()"),
                    rendered.contains("install_embedded_bootstrap_ca /opt/forge/embedded_forge_root.pem /opt/forge/forge_root.pem"),
                    rendered.contains("accept_mounted_bootstrap_ca /opt/forge/forge_root.pem"),
                    rendered.contains("  /embedded_forge_root.pem"),
                )
            },
        );
    }

    #[test]
    fn forge_agent_config() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let config = generate_forge_agent_config(interface_id, None);

        let test_config = fs::read_to_string(format!("{TEST_DATA_DIR}/agent_config.toml")).unwrap();
        assert_eq!(config, test_config);

        let data: toml::Value = toml::from_str(&config).unwrap();

        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("interface-id")
                .unwrap()
                .as_str()
                .unwrap(),
            interface_id.to_string().as_str(),
        );

        assert!(data.get("forge-system").is_none());

        let skipped = match data.get("machine").unwrap().get("is_fake_dpu") {
            Some(_val) => false,
            None => true,
        };
        assert!(skipped);
    }

    #[test]
    fn forge_agent_config_with_external_api_url() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let config = generate_forge_agent_config(interface_id, Some("https://10.99.0.1:1079"));

        let test_config =
            fs::read_to_string(format!("{TEST_DATA_DIR}/agent_config_external.toml")).unwrap();
        assert_eq!(config, test_config);

        let data: toml::Value = toml::from_str(&config).unwrap();

        assert_eq!(
            data.get("forge-system")
                .unwrap()
                .get("api-server")
                .unwrap()
                .as_str()
                .unwrap(),
            "https://10.99.0.1:1079",
        );

        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("interface-id")
                .unwrap()
                .as_str()
                .unwrap(),
            interface_id.to_string().as_str(),
        );
    }

    /// Verifies the real user-data template renders VF settings from the configured count.
    #[test]
    fn user_data_template_uses_configured_num_of_vfs() {
        let template_glob = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/templates/**/*");
        let tera = tera::Tera::new(template_glob).unwrap();

        let context = HashMap::from([
            (
                "bootstrap_ca_source".to_string(),
                "legacy_download".to_string(),
            ),
            (
                "api_url".to_string(),
                "https://carbide-api.forge".to_string(),
            ),
            (
                "forge_agent_config_b64".to_string(),
                "W21hY2hpbmVdCg==".to_string(),
            ),
            ("forge_bmc_fw_update".to_string(), String::new()),
            (
                "forge_hbn_reps".to_string(),
                "pf0hpf,pf0vf0,pf0vf2".to_string(),
            ),
            (
                "forge_host_representor_intercept_bridging".to_string(),
                String::new(),
            ),
            ("forge_hbn_bridge".to_string(), "br-hbn".to_string()),
            ("hostname".to_string(), "test-host".to_string()),
            (
                "interface_id".to_string(),
                "91609f10-c91d-470d-a260-6293ea0c1234".to_string(),
            ),
            ("num_of_vfs".to_string(), "3".to_string()),
            (
                "pxe_url".to_string(),
                "http://carbide-pxe.forge".to_string(),
            ),
            ("seconds_since_epoch".to_string(), "0".to_string()),
        ]);
        let rendered = tera
            .render(
                "user-data",
                &tera::Context::from_serialize(context).unwrap(),
            )
            .unwrap();

        assert!(rendered.contains("NUM_OF_VFS=3"));
        assert!(!rendered.contains("NUM_OF_VFS=16"));
        assert!(rendered.contains("BR_HBN_REPS=pf0hpf,pf0vf0,pf0vf2"));
        assert_eq!(rendered.matches("--physdev-in pf0vf").count(), 3);
        assert!(rendered.contains("--physdev-in pf0vf0_if"));
        assert!(rendered.contains("--physdev-in pf0vf1_if"));
        assert!(rendered.contains("--physdev-in pf0vf2_if"));
        assert!(!rendered.contains("--physdev-in pf0vf3_if"));
        assert!(rendered.contains("configure_ovn_encap_ip"));
        assert!(rendered.contains("ip -4 -o address show dev oob_net0 scope global"));
        assert!(rendered.contains("expected exactly one global IPv4 address on oob_net0"));
        assert!(rendered.contains(r#""external_ids:ovn-encap-ip=${oob_ipv4_addresses[0]}""#));
        assert!(
            rendered.find("service openvswitch-switch restart").unwrap()
                < rendered.find("configure_ovn_encap_ip\n").unwrap()
        );
    }

    /// Verifies the real user-data template renders each host representor bridge entry.
    #[test]
    fn user_data_template_renders_host_representor_intercept_bridging() {
        let template_glob = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/templates/**/*");
        let tera = tera::Tera::new(template_glob).unwrap();

        let context = HashMap::from([
            (
                "bootstrap_ca_source".to_string(),
                "legacy_download".to_string(),
            ),
            (
                "api_url".to_string(),
                "https://carbide-api.forge".to_string(),
            ),
            (
                "forge_agent_config_b64".to_string(),
                "W21hY2hpbmVdCg==".to_string(),
            ),
            ("forge_bmc_fw_update".to_string(), String::new()),
            ("forge_hbn_reps".to_string(), String::new()),
            (
                "forge_host_representor_intercept_bridging".to_string(),
                "pf0hpf:br-host:patch-br-host-to-hbn,pf0vf0:br-vf0:patch-br-vf0-to-hbn".to_string(),
            ),
            ("forge_hbn_bridge".to_string(), "br-sfc".to_string()),
            ("hostname".to_string(), "test-host".to_string()),
            (
                "interface_id".to_string(),
                "91609f10-c91d-470d-a260-6293ea0c1234".to_string(),
            ),
            ("num_of_vfs".to_string(), "3".to_string()),
            (
                "pxe_url".to_string(),
                "http://carbide-pxe.forge".to_string(),
            ),
            ("seconds_since_epoch".to_string(), "0".to_string()),
        ]);
        let rendered = tera
            .render(
                "user-data",
                &tera::Context::from_serialize(context).unwrap(),
            )
            .unwrap();

        // Verify unavailable representors do not abort the remaining cloud-init work.
        assert!(rendered.contains(
            r#"set interface "${host_representor}" type=dpdk mtu_request=9216 external_ids='{}' || true"#
        ));
        assert!(rendered.contains(
            r#"ofport_request=$(ovs-vsctl get interface "${host_representor}" ofport) || true"#
        ));
        assert!(rendered.contains("ovs-vsctl get bridge br-sfc external_ids"));
        assert!(rendered.contains("ovs-vsctl --may-exist add-port br-sfc"));
        assert!(rendered.contains(
            "host_representor_intercept_bridge_config=\"pf0hpf:br-host:patch-br-host-to-hbn\""
        ));
        assert!(rendered.contains(
            "host_representor_intercept_bridge_config=\"pf0vf0:br-vf0:patch-br-vf0-to-hbn\""
        ));
        assert_eq!(
            rendered
                .matches(r#"add_host_representor_intercept_bridge "${host_representor}" "${host_intercept_bridge_name}" "${host_intercept_bridge_port}""#)
                .count(),
            2
        );
    }

    #[test]
    fn user_data_handler_sets_fqdn_hostname() {
        let interface_id: MachineInterfaceId =
            "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let machine_interface = forge::MachineInterface {
            id: Some(interface_id),
            hostname: "node-01".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ..Default::default()
        };
        let domain = PxeDomain {
            domain: Some(forge::pxe_domain::Domain::LegacyDomain(forge::Domain {
                name: "forge.example.com".to_string(),
                ..Default::default()
            })),
        };
        let state = State(test_app_state());

        let (template_key, context) = user_data_handler(
            interface_id,
            machine_interface,
            domain,
            None,
            None,
            None,
            None,
            None,
            None,
            BootstrapCaSource::LegacyDownload,
            state,
        );

        assert_eq!(template_key, "user-data");
        assert_eq!(
            context.get("bootstrap_ca_source").map(String::as_str),
            Some("legacy_download"),
        );
        assert_eq!(
            context.get("hostname").map(String::as_str),
            Some("node-01.forge.example.com"),
        );
    }

    #[test]
    fn user_data_handler_sets_fqdn_hostname_with_new_domain() {
        let interface_id: MachineInterfaceId =
            "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let machine_interface = forge::MachineInterface {
            id: Some(interface_id),
            hostname: "node-02".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ..Default::default()
        };
        let domain = PxeDomain {
            domain: Some(forge::pxe_domain::Domain::NewDomain(rpc::dns::Domain {
                name: "new.forge.example.com".to_string(),
                ..Default::default()
            })),
        };
        let state = State(test_app_state());

        let (_template_key, context) = user_data_handler(
            interface_id,
            machine_interface,
            domain,
            None,
            None,
            None,
            None,
            None,
            None,
            BootstrapCaSource::LegacyDownload,
            state,
        );

        assert_eq!(
            context.get("hostname").map(String::as_str),
            Some("node-02.new.forge.example.com"),
        );
    }

    /// Table-driven coverage for `extract_network_config` across its three
    /// input variants: a present `network:` key, a missing one, and
    /// malformed YAML.
    #[test]
    fn extract_network_config_handles_various_inputs() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expect_some: bool,
        }

        let cases = [
            Case {
                name: "network key present",
                input: "#cloud-config\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 10.10.10.50/24\nwrite_files:\n  - path: /tmp/foo\n    content: bar\n",
                expect_some: true,
            },
            Case {
                name: "no network key",
                input: "#cloud-config\nwrite_files:\n  - path: /tmp/foo\n    content: bar\n",
                expect_some: false,
            },
            Case {
                name: "invalid yaml",
                input: "not: valid: yaml: at: all: :::",
                expect_some: false,
            },
        ];

        for case in cases {
            let result = extract_network_config(case.input);
            assert_eq!(
                result.is_some(),
                case.expect_some,
                "case '{}' failed",
                case.name
            );

            if case.expect_some {
                let parsed: serde_yaml::Value = serde_yaml::from_str(&result.unwrap()).unwrap();
                assert_eq!(parsed.get("version").unwrap().as_u64().unwrap(), 2);
                assert!(
                    parsed
                        .get("ethernets")
                        .and_then(|e| e.get("eth0"))
                        .is_some(),
                    "case '{}': expected eth0 config present",
                    case.name
                );
            }
        }
    }

    #[test]
    fn resolve_network_config_handles_various_inputs() {
        struct Case {
            name: &'static str,
            custom_cloud_init: Option<&'static str>,
            expect_default: bool,
        }

        let cases = [
            Case {
                name: "no network key in custom cloud-init",
                custom_cloud_init: Some("#cloud-config\nwrite_files: []\n"),
                expect_default: true,
            },
            Case {
                name: "network key present in custom cloud-init",
                custom_cloud_init: Some(
                    "#cloud-config\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 10.10.10.50/24\n",
                ),
                expect_default: false,
            },
            Case {
                name: "no custom cloud-init at all",
                custom_cloud_init: None,
                expect_default: true,
            },
        ];

        for case in cases {
            let result = resolve_network_config(case.custom_cloud_init);

            if case.expect_default {
                assert_eq!(
                    result, DEFAULT_NETWORK_CONFIG,
                    "case '{}' failed",
                    case.name
                );
            } else {
                let parsed: serde_yaml::Value = serde_yaml::from_str(&result).unwrap_or_else(|e| {
                    panic!("case '{}': result was not valid YAML: {}", case.name, e)
                });
                assert_eq!(
                    parsed.get("version").unwrap().as_u64().unwrap(),
                    2,
                    "case '{}' failed",
                    case.name
                );
                let eth0_addresses = parsed
                    .get("ethernets")
                    .and_then(|e| e.get("eth0"))
                    .and_then(|e| e.get("addresses"))
                    .and_then(|a| a.as_sequence())
                    .unwrap_or_else(|| {
                        panic!("case '{}': expected ethernets.eth0.addresses", case.name)
                    });
                assert_eq!(
                    eth0_addresses[0].as_str().unwrap(),
                    "10.10.10.50/24",
                    "case '{}' failed",
                    case.name
                );
            }
        }
    }

    fn test_app_state_with_templates() -> AppState {
        use axum_template::engine::Engine;
        use metrics_exporter_prometheus::PrometheusBuilder;
        use tera::Tera;

        let template_glob = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/templates/**/*");
        let tera = Tera::new(template_glob).expect("failed to load pxe templates");
        let mut state = test_app_state();
        state.engine = Engine::from(tera);
        state.prometheus_handle = PrometheusBuilder::new().build_recorder().handle();
        state
    }

    /// When an instance has a name, meta-data includes local-hostname so
    /// cloud-init sets the OS hostname via the NoCloud datasource.
    #[tokio::test]
    async fn meta_data_includes_local_hostname_when_instance_has_name() {
        let response = meta_data(
            Machine {
                instructions: forge::CloudInitInstructions {
                    metadata: Some(forge::CloudInitMetaData {
                        instance_id: "test-instance-id".to_string(),
                        cloud_name: "nvidia".to_string(),
                        platform: "forge".to_string(),
                        local_hostname: "my-node".to_string(),
                    }),
                    ..Default::default()
                },
            },
            State(test_app_state_with_templates()),
        )
        .await
        .into_response();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("local-hostname: \"my-node\""),
            "meta-data should contain local-hostname, got: {text}"
        );
    }

    /// When an instance has no name, meta-data must not include local-hostname
    /// so cloud-init falls back to its default hostname derivation.
    #[tokio::test]
    async fn meta_data_omits_local_hostname_when_instance_has_no_name() {
        let response = meta_data(
            Machine {
                instructions: forge::CloudInitInstructions {
                    metadata: Some(forge::CloudInitMetaData {
                        instance_id: "test-instance-id".to_string(),
                        cloud_name: "nvidia".to_string(),
                        platform: "forge".to_string(),
                        local_hostname: String::new(),
                    }),
                    ..Default::default()
                },
            },
            State(test_app_state_with_templates()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            !text.contains("local-hostname"),
            "meta-data must not contain local-hostname when name is empty, got: {text}"
        );
    }

    /// A meta-data request with no metadata lands in the generic-error
    /// funnel, which serves the error template and moves the outcome
    /// counter.
    #[tokio::test]
    async fn meta_data_without_metadata_counts_metadata_not_found() {
        let metrics = MetricsCapture::start();

        let _ = meta_data(
            Machine {
                instructions: Default::default(),
            },
            State(test_app_state()),
        )
        .await;

        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "cloud_init"), ("reason", "metadata_not_found")],
            ),
            1.0,
        );
    }

    /// A user-data request answered from the tenant's custom cloud-init
    /// counts as a served outcome.
    #[tokio::test]
    async fn user_data_with_custom_cloud_init_counts_ok() {
        let metrics = MetricsCapture::start();

        let _ = user_data(
            Machine {
                instructions: forge::CloudInitInstructions {
                    custom_cloud_init: Some("#cloud-config".to_string()),
                    ..Default::default()
                },
            },
            State(test_app_state()),
        )
        .await;

        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "cloud_init"), ("reason", "ok")],
            ),
            1.0,
        );
    }
}
