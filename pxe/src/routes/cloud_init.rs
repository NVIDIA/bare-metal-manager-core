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
use base64::prelude::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rocket::get;
use rocket::routes;
use rocket::Route;
use rocket_dyn_templates::Template;
use rpc::forge;

use crate::{Machine, RuntimeConfig};
use forge_host_support::agent_config;

fn user_data_handler(
    machine_interface_id: rpc::Uuid,
    machine_interface: forge::MachineInterface,
    update_firmware: bool,
    domain: forge::Domain,
    config: RuntimeConfig,
) -> (String, HashMap<String, String>) {
    let forge_agent_config =
        generate_forge_agent_config(&machine_interface_id, &machine_interface, &domain, &config);

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
    context.insert("ntp_server".to_string(), config.ntp_server);
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

    context.insert(
        "dpu_agent_pkg_version".to_string(),
        forge_version::v!(build_version)[1..].to_string(),
    );

    ("user-data".to_string(), context)
}

/// Generates the content of the /etc/forge/config.toml file
fn generate_forge_agent_config(
    machine_interface_id: &rpc::Uuid,
    machine_interface: &forge::MachineInterface,
    domain: &forge::Domain,
    config: &RuntimeConfig,
) -> String {
    let api_url = config.client_facing_api_url.clone();
    let pxe_url = config.pxe_url.clone();
    let ntp_server = config.ntp_server.clone();

    let interface_id = uuid::Uuid::parse_str(&machine_interface_id.to_string()).unwrap();
    let mac_address = machine_interface.mac_address.clone();
    let hostname = format!("{}.{}", machine_interface.hostname, domain.name);

    // TODO we need to figure out the addresses on which those services should run
    let instance_metadata_service_address = "0.0.0.0:7777";
    let telemetry_metrics_service_address = "0.0.0.0:8888";

    let config = agent_config::AgentConfig {
        forge_system: agent_config::ForgeSystemConfig {
            api_server: api_url,
            pxe_server: Some(pxe_url),
            ntp_server: Some(ntp_server),
            // TODO: These should *probably* just inherit from
            // RuntimeConfig, but for whatever reason these have
            // historically been ignored here, so leaving as-is
            // for the time being.
            root_ca: agent_config::default_root_ca(),
            client_cert: agent_config::default_client_cert(),
            client_key: agent_config::default_client_key(),
        },

        machine: agent_config::MachineConfig {
            interface_id,
            mac_address: Some(mac_address),
            hostname: Some(hostname),
            override_upgrade_cmd: None,
            // This will get stripped from the serialized config
            // as part of the default value being excluded.
            is_fake_dpu: false,
        },

        metadata_service: Some(agent_config::MetadataServiceConfig {
            address: instance_metadata_service_address.to_string(),
        }),

        telemetry: Some(agent_config::TelemetryConfig {
            metrics_address: telemetry_metrics_service_address.to_string(),
        }),

        // TODO: In the original implementation of how we'd
        // build a string for this config, these were excluded
        // entirely. Now they're being passed w/ their default
        // values. Good? Or should we do some work to skip
        // serialization here?
        hbn: agent_config::HBNConfig::default(),
        period: agent_config::IterationTime::default(),
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
        (None, None) => print_and_generate_generic_error(
            "The custom cloud init and discovery instructions were both None".to_string(),
        ),
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
    use super::*;
    use std::fs;

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
        };

        let domain = rpc::Domain {
            id: None,
            name: "myforge.com".to_string(),
            created: None,
            updated: None,
            deleted: None,
        };

        let runtime_config = RuntimeConfig {
            internal_api_url: "https://127.0.0.1:8001".to_string(),
            client_facing_api_url: "https://127.0.0.1:8001".to_string(),
            pxe_url: "http://127.0.0.1:8080".to_string(),
            ntp_server: "127.0.0.2".to_string(),
            forge_root_ca_path: rpc::forge_tls_client::DEFAULT_ROOT_CA.to_string(),
            server_cert_path: rpc::forge_tls_client::DEFAULT_CLIENT_CERT.to_string(),
            server_key_path: rpc::forge_tls_client::DEFAULT_CLIENT_KEY.to_string(),
        };

        let interface_id: rpc::Uuid = interface.id.clone().unwrap();

        let config =
            generate_forge_agent_config(&interface_id, &interface, &domain, &runtime_config);

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
            data.get("forge-system")
                .unwrap()
                .get("api-server")
                .unwrap()
                .as_str()
                .unwrap(),
            "https://127.0.0.1:8001"
        );
        assert_eq!(
            data.get("forge-system")
                .unwrap()
                .get("pxe-server")
                .unwrap()
                .as_str()
                .unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            data.get("forge-system")
                .unwrap()
                .get("ntp-server")
                .unwrap()
                .as_str()
                .unwrap(),
            "127.0.0.2"
        );

        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("interface-id")
                .unwrap()
                .as_str()
                .unwrap(),
            "91609f10-c91d-470d-a260-6293ea0c1234"
        );
        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("mac-address")
                .unwrap()
                .as_str()
                .unwrap(),
            "01:02:03:AA:BB:CC"
        );
        assert_eq!(
            data.get("machine")
                .unwrap()
                .get("hostname")
                .unwrap()
                .as_str()
                .unwrap(),
            "abc.myforge.com"
        );

        // Check to make sure is_fake_dpu gets skipped
        // from the serialized output.
        let skipped = match data.get("machine").unwrap().get("is_fake_dpu") {
            Some(_val) => false,
            None => true,
        };
        assert!(skipped);

        assert_eq!(
            data.get("metadata-service")
                .unwrap()
                .get("address")
                .unwrap()
                .as_str()
                .unwrap(),
            "0.0.0.0:7777"
        );

        assert_eq!(
            data.get("telemetry")
                .unwrap()
                .get("metrics-address")
                .unwrap()
                .as_str()
                .unwrap(),
            "0.0.0.0:8888"
        );
    }
}
