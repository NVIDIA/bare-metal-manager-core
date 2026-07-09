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

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum_template::TemplateEngine;
use base64::Engine as _;
use carbide_host_support::agent_config;
use carbide_instrument::emit;
use carbide_uuid::machine::MachineInterfaceId;
use rpc::forge;
use rpc::forge::PxeDomain;

use crate::common::{AppState, Machine};
use crate::metrics::{BootEndpoint, OutcomeReason, PxeBootOutcome};

const DEFAULT_NUM_OF_VFS: u32 = 16;
const DEFAULT_HBN_BRIDGE: &str = "br-hbn";

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
fn print_and_generate_generic_error(
    error: String,
    reason: OutcomeReason,
) -> (String, HashMap<String, String>) {
    eprintln!("{error}");
    emit(PxeBootOutcome {
        endpoint: BootEndpoint::CloudInit,
        reason,
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
    hbn_sfs: Option<String>,
    num_of_vfs: Option<u32>,
    vf_intercept_bridge_name: Option<String>,
    host_representor_intercept_bridging: Option<String>,
    hbn_bridge: Option<String>,
    vf_intercept_bridge_port: Option<String>,
    vf_intercept_bridge_sf: Option<String>,
    api_url_override: Option<String>,
    pxe_url_override: Option<String>,
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
    // Use URL overrides for external clients (static-assignments segment),
    // falling back to global config.
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

    if let Some(hbn_sfs) = hbn_sfs {
        context.insert("forge_hbn_sfs".to_string(), hbn_sfs);
    }

    let num_of_vfs = num_of_vfs.unwrap_or(DEFAULT_NUM_OF_VFS);
    context.insert("num_of_vfs".to_string(), num_of_vfs.to_string());
    context.insert(
        "forge_hbn_bridge".to_string(),
        hbn_bridge.unwrap_or_else(|| DEFAULT_HBN_BRIDGE.to_string()),
    );

    if let Some(vf_intercept_bridge_name) = vf_intercept_bridge_name {
        context.insert(
            "forge_vf_intercept_bridge_name".to_string(),
            vf_intercept_bridge_name,
        );
    }

    if let Some(host_representor_intercept_bridging) = host_representor_intercept_bridging {
        context.insert(
            "forge_host_representor_intercept_bridging".to_string(),
            host_representor_intercept_bridging,
        );
    }

    if let Some(vf_intercept_bridge_port) = vf_intercept_bridge_port {
        context.insert(
            "forge_vf_intercept_hbn_port".to_string(),
            format!("patch-hbn-{vf_intercept_bridge_port}"),
        );

        context.insert(
            "forge_vf_intercept_bridge_port".to_string(),
            vf_intercept_bridge_port,
        );
    }

    if let Some(vf_intercept_bridge_sf) = vf_intercept_bridge_sf {
        context.insert(
            "forge_vf_intercept_bridge_sf_representor".to_string(),
            format!("{vf_intercept_bridge_sf}_r"),
        );

        context.insert(
            "forge_vf_intercept_bridge_sf_hbn_bridge_representor".to_string(),
            format!("{vf_intercept_bridge_sf}_if_r"),
        );

        context.insert(
            "forge_vf_intercept_bridge_sf".to_string(),
            vf_intercept_bridge_sf,
        );
    }

    ("user-data".to_string(), context)
}

pub async fn user_data(machine: Machine, state: State<AppState>) -> impl IntoResponse {
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
                        emit(PxeBootOutcome {
                            endpoint: BootEndpoint::CloudInit,
                            reason: OutcomeReason::Ok,
                        });
                        user_data_handler(
                            machine_interface_id,
                            interface,
                            domain,
                            discovery_instructions.hbn_reps,
                            discovery_instructions.hbn_sfs,
                            discovery_instructions.num_of_vfs,
                            discovery_instructions.vf_intercept_bridge_name,
                            discovery_instructions.host_representor_intercept_bridging,
                            discovery_instructions.hbn_bridge,
                            discovery_instructions.vf_intercept_bridge_port,
                            discovery_instructions.vf_intercept_bridge_sf,
                            machine.instructions.api_url_override,
                            machine.instructions.pxe_url_override,
                            state.clone(),
                        )
                    }
                    None => print_and_generate_generic_error(
                        format!("The interface ID should not be null: {interface:?}"),
                        OutcomeReason::InterfaceNotFound,
                    ),
                },
                (interface, domain) => print_and_generate_generic_error(
                    format!("The interface and domain were not found: {interface:?}, {domain:?}"),
                    OutcomeReason::InterfaceNotFound,
                ),
            }
        }
        // discovery_instructions can not be None for a non-assigned machine.
        // This means that the machine is assigned to tenant.
        // custom_cloud_init None means user has not configured any user-data. Send a empty
        // response.
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

pub async fn meta_data(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let (template_key, template_data) = match machine.instructions.metadata {
        None => print_and_generate_generic_error(
            format!("No metadata was found for machine {machine:?}"),
            OutcomeReason::MetadataNotFound,
        ),
        Some(metadata) => {
            let template_data = HashMap::from([
                ("instance_id".to_string(), metadata.instance_id),
                ("cloud_name".to_string(), metadata.cloud_name),
                ("platform".to_string(), metadata.platform),
            ]);

            emit(PxeBootOutcome {
                endpoint: BootEndpoint::CloudInit,
                reason: OutcomeReason::Ok,
            });
            ("meta-data".to_string(), template_data)
        }
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

pub async fn vendor_data(state: State<AppState>) -> impl IntoResponse {
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

pub fn get_router(path_prefix: &str) -> Router<AppState> {
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
}

#[cfg(test)]
mod tests {
    use std::fs;

    use carbide_instrument::testing::MetricsCapture;

    use super::*;
    use crate::common::test_app_state;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/test_data");

    #[test]
    fn forge_agent_config() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let config = generate_forge_agent_config(interface_id, None);

        // The intent here is to actually test what the written
        // configuration file looks like, so we can visualize to
        // make sure it's going to look like what we think it's
        // supposed to look like. Obviously as various new fields
        // get added to AgentConfig, then our test config will also
        // need to be updated accordingly, but that should be ok.
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

        // No forge-system section when no override is provided.
        assert!(data.get("forge-system").is_none());

        // Check to make sure is_fake_dpu gets skipped
        // from the serialized output.
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

        // Use the same string-valued context shape the route handler passes to Tera.
        let context = HashMap::from([
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
            ("forge_hbn_sfs".to_string(), String::new()),
            (
                "forge_host_representor_intercept_bridging".to_string(),
                String::new(),
            ),
            ("forge_hbn_bridge".to_string(), "br-hbn".to_string()),
            ("forge_vf_intercept_bridge_name".to_string(), String::new()),
            ("forge_vf_intercept_bridge_port".to_string(), String::new()),
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

        // The mlxconfig value and DHCP drop rules should use the configured count.
        assert!(rendered.contains("NUM_OF_VFS=3"));
        assert!(!rendered.contains("NUM_OF_VFS=16"));
        assert_eq!(rendered.matches("--physdev-in pf0vf").count(), 3);
        assert!(rendered.contains("--physdev-in pf0vf0_if"));
        assert!(rendered.contains("--physdev-in pf0vf1_if"));
        assert!(rendered.contains("--physdev-in pf0vf2_if"));
        assert!(!rendered.contains("--physdev-in pf0vf3_if"));
    }

    /// Verifies the real user-data template renders each host representor bridge entry.
    #[test]
    fn user_data_template_renders_host_representor_intercept_bridging() {
        let template_glob = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/templates/**/*");
        let tera = tera::Tera::new(template_glob).unwrap();

        // Use a non-empty provisioning string so the host representor bridge loop renders.
        let context = HashMap::from([
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
            ("forge_hbn_sfs".to_string(), String::new()),
            (
                "forge_host_representor_intercept_bridging".to_string(),
                "pf0hpf:br-host:patch-br-host-to-hbn,pf0vf0:br-vf0:patch-br-vf0-to-hbn".to_string(),
            ),
            ("forge_hbn_bridge".to_string(), "br-sfc".to_string()),
            ("forge_vf_intercept_bridge_name".to_string(), String::new()),
            ("forge_vf_intercept_bridge_port".to_string(), String::new()),
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

        // The loop should emit one assignment and invocation per bridge entry.
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
            None,
            None,
            None,
            None,
            state,
        );

        assert_eq!(template_key, "user-data");
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
            None,
            None,
            None,
            None,
            state,
        );

        assert_eq!(
            context.get("hostname").map(String::as_str),
            Some("node-02.new.forge.example.com"),
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
