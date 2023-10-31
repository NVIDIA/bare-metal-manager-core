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
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
        base64::encode(forge_agent_config),
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
    let api_url = config.client_facing_api_url.as_str();
    let pxe_url = config.pxe_url.as_str();
    let ntp_server = config.ntp_server.as_str();

    let mac_address = machine_interface.mac_address.clone();
    let hostname = format!("{}.{}", machine_interface.hostname, domain.name);

    // TODO we need to figure out the addresses on which those services should run
    let instance_metadata_service_address = "0.0.0.0:7777";
    let telemetry_metrics_service_address = "0.0.0.0:8888";

    let content = format!(
        "
        [forge-system]
        api-server = \"{api_url}\"
        pxe-server = \"{pxe_url}\"
        ntp-server = \"{ntp_server}\"

        [machine]
        interface-id = \"{machine_interface_id}\"
        mac-address = \"{mac_address}\"
        hostname = \"{hostname}\"
        upgrade-cmd = \"apt-get update -o Dir::Etc::sourcelist=sources.list.d/forge.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 && apt-get install --yes --only-upgrade forge-dpu=__PKG_VERSION__\"

        [metadata-service]
        address = \"{instance_metadata_service_address}\"

        [telemetry]
        metrics-address = \"{telemetry_metrics_service_address}\"
        "
    );

    let mut lines: Vec<&str> = content.split('\n').map(|line| line.trim_start()).collect();
    while let Some(line) = lines.first() {
        if line.is_empty() {
            lines.remove(0);
        } else {
            break;
        }
    }

    lines.join("\n")
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
