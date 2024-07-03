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

// Rust somewhere 1.71->1.76 added a lint that doesn't like Rocket
#![allow(unused_imports)]

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use forge_host_support::agent_config;
use rocket::get;
use rocket::routes;
use rocket::Route;
use rocket_dyn_templates::Template;
use rpc::forge;

use crate::{Machine, RuntimeConfig};

fn user_data_handler(
    machine_interface_id: rpc::Uuid,
    machine_interface: forge::MachineInterface,
    update_firmware: bool,
    domain: forge::Domain,
    config: RuntimeConfig,
) -> (String, HashMap<String, String>) {
    let forge_agent_config = generate_forge_agent_config(&machine_interface_id);

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine_interface.mac_address);

    // IMPORTANT: if the nic fw update and the hbn are both yes, it puts the dpu into a state that requires a power down.
    if update_firmware {
        context.insert("update_firmware".to_owned(), "true".to_owned());
    } else {
        context.insert("update_firmware".to_owned(), "false".to_owned());
    }

    context.insert(
        "hostname".to_string(),
        format!("{}.{}", machine_interface.hostname, domain.name),
    );
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert("api_url".to_string(), config.client_facing_api_url);
    context.insert("pxe_url".to_string(), config.pxe_url);
    context.insert(
        "forge_agent_config_b64".to_string(),
        BASE64_STANDARD.encode(forge_agent_config),
    );

    let start = SystemTime::now();
    let seconds_since_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    context.insert(
        "seconds_since_epoch".to_string(),
        seconds_since_epoch.to_string(),
    );

    ("user-data".to_string(), context)
}

/// Generates the content of the /etc/forge/config.toml file
//
// TODO(chet): This should take a MachineInterfaceId, but I think by doing that,
// then agent_config (which is in host-support), would need to import forge-api,
// which I think would then make it so scout + the agent start having a dep on
// api/ -- I don't think it's a problem, but I'll propose it in a separate MR.
fn generate_forge_agent_config(machine_interface_id: &rpc::Uuid) -> String {
    let interface_id = uuid::Uuid::parse_str(&machine_interface_id.to_string()).unwrap();
    let config = agent_config::AgentConfigFromPxe {
        machine: agent_config::MachineConfigFromPxe { interface_id },
    };

    toml::to_string(&config).unwrap()
}

fn print_and_generate_generic_error(error: String) -> (String, HashMap<String, String>) {
    eprintln!("{error}");
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert(
        "error".to_string(),
        "An error occurred while rendering the user-data".to_string(),
    );
    ("error".to_string(), context) // Send a generic error back
}

#[get("/user-data")]
pub async fn user_data(machine: Machine, config: RuntimeConfig) -> Template {
    let (template, context) = match (
        machine.instructions.custom_cloud_init,
        machine.instructions.discovery_instructions,
    ) {
        (Some(custom_cloud_init), _) => {
            let mut context: HashMap<String, String> = HashMap::new();
            context.insert("user_data".to_string(), custom_cloud_init);
            ("user-data-assigned".to_string(), context)
        }
        (None, Some(discovery_instructions)) => {
            match (
                discovery_instructions.machine_interface,
                discovery_instructions.domain,
            ) {
                (Some(interface), Some(domain)) => match interface.id.clone() {
                    Some(machine_interface_id) => user_data_handler(
                        machine_interface_id,
                        interface,
                        discovery_instructions.update_firmware,
                        domain,
                        config,
                    ),
                    None => print_and_generate_generic_error(format!(
                        "The interface ID should not be null: {:?}",
                        interface
                    )),
                },
                (d, i) => print_and_generate_generic_error(format!(
                    "The interface and domain were not found: {:?}, {:?}",
                    i, d
                )),
            }
        }
        // discovery_instructions can not be None for a non-assigned machine.
        // This means that the machine is assigned to tenant.
        // custom_cloud_init None means user has not configured any user-data. Send a empty
        // response.
        (None, None) => {
            let mut context: HashMap<String, String> = HashMap::new();
            context.insert("user_data".to_string(), "{}".to_string());
            ("user-data-assigned".to_string(), context)
        }
    };

    Template::render(template, context)
}

#[get("/meta-data")]
pub async fn meta_data(machine: Machine) -> Template {
    let (template, context) = match machine.instructions.metadata {
        None => print_and_generate_generic_error(format!(
            "No metadata was found for machine {:?}",
            machine
        )),
        Some(metadata) => {
            let context = HashMap::from([
                ("instance_id".to_string(), metadata.instance_id),
                ("cloud_name".to_string(), metadata.cloud_name),
                ("platform".to_string(), metadata.platform),
            ]);

            ("meta-data".to_string(), context)
        }
    };

    Template::render(template, context)
}

#[get("/vendor-data")]
pub async fn vendor_data() -> Template {
    Template::render("printcontext", HashMap::<String, String>::new())
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data, vendor_data]
}

#[cfg(test)]
mod tests {
    use std::fs;

    use forge_tls::default as tls_default;

    use super::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data");

    #[test]
    fn forge_agent_config() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".to_string();

        let interface = rpc::forge::MachineInterface {
            id: Some(rpc::Uuid {
                value: interface_id,
            }),
            attached_dpu_machine_id: Some(rpc::MachineId {
                id: "91609f10-c91d-470d-a260-6293ea0c0000".to_string(),
            }),
            machine_id: Some(rpc::MachineId {
                id: "91609f10-c91d-470d-a260-6293ea0c0000".to_string(),
            }),
            segment_id: None,
            hostname: "abc".to_string(),
            domain_id: None,
            primary_interface: true,
            mac_address: "01:02:03:AA:BB:CC".to_string(),
            address: vec!["192.123.184.244".to_string()],
            vendor: Some("xyz".to_string()),
            created: None,
            last_dhcp: None,
        };

        let interface_id: rpc::Uuid = interface.id.clone().unwrap();
        let config = generate_forge_agent_config(&interface_id);

        // The intent here is to actually test what the written
        // configuration file looks like, so we can visualize to
        // make sure it's going to look like what we think it's
        // supposed to look like. Obviously as various new fields
        // get added to AgentConfig, then our test config will also
        // need to be updated accordingly, but that should be ok.
        let test_config =
            fs::read_to_string(format!("{}/agent_config.toml", TEST_DATA_DIR)).unwrap();
        assert_eq!(config, test_config);

        let data: toml::Value = config.parse().unwrap();

        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("interface-id")
                .unwrap()
                .as_str()
                .unwrap(),
            "91609f10-c91d-470d-a260-6293ea0c1234"
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
