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
use carbide_uuid::machine::MachineInterfaceId;
use rpc::forge;
use rpc::forge::PxeDomain;

use crate::common::{AppState, Machine};
/// Generates the content of the /etc/forge/config.toml file
//
// TODO(chet): This should take a MachineInterfaceId, but I think by doing that,
// then agent_config (which is in host-support), would need to import forge-api,
// which I think would then make it so scout + the agent start having a dep on
// api/ -- I don't think it's a problem, but I'll propose it in a separate MR.
fn generate_forge_agent_config(machine_interface_id: MachineInterfaceId) -> String {
    let interface_id = uuid::Uuid::parse_str(&machine_interface_id.to_string()).unwrap();
    let config = agent_config::AgentConfigFromPxe {
        machine: agent_config::MachineConfigFromPxe { interface_id },
    };

    toml::to_string(&config).unwrap()
}

fn print_and_generate_generic_error(error: String) -> (String, HashMap<String, String>) {
    eprintln!("{error}");
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
    vf_intercept_bridge_name: Option<String>,
    host_intercept_bridge_name: Option<String>,
    host_intercept_bridge_port: Option<String>,
    vf_intercept_bridge_port: Option<String>,
    vf_intercept_bridge_sf: Option<String>,
    state: State<AppState>,
) -> (String, HashMap<String, String>) {
    let config = state.runtime_config.clone();
    let forge_agent_config = generate_forge_agent_config(machine_interface_id);

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine_interface.mac_address);

    if let Some(domain_oneof) = domain.domain {
        match domain_oneof {
            forge::pxe_domain::Domain::LegacyDomain(domain) => {
                context.insert("hostname".to_string(), domain.name);
            }
            forge::pxe_domain::Domain::NewDomain(domain) => {
                context.insert("hostname".to_string(), domain.name);
            }
        }
    }
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert("api_url".to_string(), config.client_facing_api_url);
    context.insert("pxe_url".to_string(), config.pxe_url);
    context.insert(
        "forge_agent_config_b64".to_string(),
        base64::engine::general_purpose::STANDARD.encode(forge_agent_config),
    );

    let bmc_fw_update = state
        .engine
        .render("bmc_fw_update", HashMap::<String, String>::new())
        .unwrap_or("".to_string());
    context.insert("forge_bmc_fw_update".to_string(), bmc_fw_update);

    let start = SystemTime::now();
    let seconds_since_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
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

    if let Some(vf_intercept_bridge_name) = vf_intercept_bridge_name {
        context.insert(
            "forge_vf_intercept_bridge_name".to_string(),
            vf_intercept_bridge_name,
        );
    }

    if let Some(host_intercept_bridge_name) = host_intercept_bridge_name {
        context.insert(
            "forge_host_intercept_bridge_name".to_string(),
            host_intercept_bridge_name,
        );
    }

    if let Some(host_intercept_bridge_port) = host_intercept_bridge_port {
        context.insert(
            "forge_host_intercept_hbn_port".to_string(),
            format!("patch-hbn-{host_intercept_bridge_port}"),
        );

        context.insert(
            "forge_host_intercept_bridge_port".to_string(),
            host_intercept_bridge_port,
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
            ("user-data-assigned".to_string(), template_data)
        }
        (None, Some(discovery_instructions)) => {
            match (
                discovery_instructions.machine_interface,
                discovery_instructions.domain,
            ) {
                (Some(interface), Some(domain)) => match interface.id {
                    Some(machine_interface_id) => user_data_handler(
                        machine_interface_id,
                        interface,
                        domain,
                        discovery_instructions.hbn_reps,
                        discovery_instructions.hbn_sfs,
                        discovery_instructions.vf_intercept_bridge_name,
                        discovery_instructions.host_intercept_bridge_name,
                        discovery_instructions.host_intercept_bridge_port,
                        discovery_instructions.vf_intercept_bridge_port,
                        discovery_instructions.vf_intercept_bridge_sf,
                        state.clone(),
                    ),
                    None => print_and_generate_generic_error(format!(
                        "The interface ID should not be null: {interface:?}"
                    )),
                },
                (d, i) => print_and_generate_generic_error(format!(
                    "The interface and domain were not found: {i:?}, {d:?}"
                )),
            }
        }
        // discovery_instructions can not be None for a non-assigned machine.
        // This means that the machine is assigned to tenant.
        // custom_cloud_init None means user has not configured any user-data. Send a empty
        // response.
        (None, None) => {
            let mut template_data: HashMap<String, String> = HashMap::new();
            template_data.insert("user_data".to_string(), "{}".to_string());
            ("user-data-assigned".to_string(), template_data)
        }
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

pub async fn meta_data(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let (template_key, template_data) = match machine.instructions.metadata {
        None => print_and_generate_generic_error(format!(
            "No metadata was found for machine {machine:?}"
        )),
        Some(metadata) => {
            let template_data = HashMap::from([
                ("instance_id".to_string(), metadata.instance_id),
                ("cloud_name".to_string(), metadata.cloud_name),
                ("platform".to_string(), metadata.platform),
            ]);

            ("meta-data".to_string(), template_data)
        }
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

pub async fn vendor_data(state: State<AppState>) -> impl IntoResponse {
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

    use super::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pxe/test_data");

    #[test]
    fn forge_agent_config() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".parse().unwrap();
        let config = generate_forge_agent_config(interface_id);

        // The intent here is to actually test what the written
        // configuration file looks like, so we can visualize to
        // make sure it's going to look like what we think it's
        // supposed to look like. Obviously as various new fields
        // get added to AgentConfig, then our test config will also
        // need to be updated accordingly, but that should be ok.
        let test_config = fs::read_to_string(format!("{TEST_DATA_DIR}/agent_config.toml")).unwrap();
        assert_eq!(config, test_config);

        let data: toml::Value = config.parse().unwrap();

        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("interface-id")
                .unwrap()
                .as_str()
                .unwrap(),
            interface_id.to_string().as_str(),
        );

        // Check to make sure is_fake_dpu gets skipped
        // from the serialized output.
        let skipped = match data.get("machine").unwrap().get("is_fake_dpu") {
            Some(_val) => false,
            None => true,
        };
        assert!(skipped);
    }
}
