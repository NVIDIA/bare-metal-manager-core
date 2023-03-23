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
use rocket::serde::uuid;
use rocket::Route;
use rocket_dyn_templates::Template;

use crate::{routes::RpcContext, Machine, RuntimeConfig};

async fn user_data_handler_in_assigned(
    machine: Machine,
    config: RuntimeConfig,
) -> (String, HashMap<String, String>) {
    let machine_id = machine.machine.and_then(|m| m.id);

    let user_data = match &machine_id {
        Some(rpc_machine) => {
            match RpcContext::get_instance(rpc_machine.clone(), config.api_url.clone()).await {
                Ok(rpc::Instance {
                    config:
                        Some(rpc::InstanceConfig {
                            tenant: Some(tenant_config),
                            ..
                        }),
                    ..
                }) => tenant_config
                    .user_data
                    .unwrap_or_else(|| "User data is not available.".to_string()),
                Ok(_) => {
                    // TODO: We shouldn't really pass this into the as PXE user-data?
                    // However there is currently no way to return an error from here,
                    // and the error branch below does the same
                    let error = format!(
                        "Missing TenantConfig in instance for Machine {}",
                        rpc_machine
                    );
                    eprintln!("{}", error);
                    error
                }
                Err(err) => {
                    eprintln!("{}", err);
                    format!("Failed to fetch user_data: {}", err)
                }
            }
        }
        None => "Failed to fetch machine_details.".to_string(),
    };

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("user_data".to_string(), user_data);
    ("user-data-assigned".to_string(), context)
}

async fn user_data_handler(
    machine_interface_id: uuid::Uuid,
    machine: Machine,
    config: RuntimeConfig,
) -> (String, HashMap<String, String>) {
    let forge_agent_config = generate_forge_agent_config(machine_interface_id, &machine, &config);

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine.interface.mac_address);
    context.insert(
        "hostname".to_string(),
        format!("{}.{}", machine.interface.hostname, machine.domain.name),
    );
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert("api_url".to_string(), config.api_url);
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

    ("user-data".to_string(), context)
}

/// Generates the content of the /etc/forge/config.toml file
fn generate_forge_agent_config(
    machine_interface_id: uuid::Uuid,
    machine: &Machine,
    config: &RuntimeConfig,
) -> String {
    let api_url = config.api_url.as_str();
    let pxe_url = config.pxe_url.as_str();
    let ntp_server = config.ntp_server.as_str();

    let mac_address = machine.interface.mac_address.clone();
    let hostname = format!("{}.{}", machine.interface.hostname, machine.domain.name);

    let content = format!(
        "
        [forge-system]
        api-server = \"{api_url}\"
        pxe-server = \"{pxe_url}\"
        ntp-server = \"{ntp_server}\"
        
        [machine]
        interface-id = \"{machine_interface_id}\"
        mac-address = \"{mac_address}\"
        hostname = \"{hostname}\""
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

#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine, config: RuntimeConfig) -> Template {
    let (template, context) = match machine.machine.as_ref() {
        Some(rpc_machine) if rpc_machine.state == "assigned" => {
            user_data_handler_in_assigned(machine, config).await
        }

        _ => user_data_handler(uuid, machine, config).await,
    };
    Template::render(template, context)
}

#[get("/<uuid>/meta-data")]
pub async fn meta_data(uuid: uuid::Uuid) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();

    //insert it into the context just to use the variable
    //TODO: figure how what to actually use the UUID for later
    context.insert("uuid".to_string(), uuid.to_string());

    Template::render("printcontext", &context)
}

#[get("/<uuid>/vendor-data")]
pub async fn vendor_data(uuid: uuid::Uuid) -> Template {
    // placeholder content stolen from the meta_data call above
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("uuid".to_string(), uuid.to_string());
    Template::render("printcontext", &context)
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data, vendor_data]
}

#[cfg(test)]
mod tests {
    use rpc::forge::MachineType;

    use super::*;

    #[test]
    fn forge_agent_config() {
        let interface_id = "91609f10-c91d-470d-a260-6293ea0c1234".to_string();

        let interface = rpc::forge::MachineInterface {
            id: Some(rpc::Uuid {
                value: interface_id.clone(),
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
        };

        let machine = Machine {
            architecture: Some(rpc::forge::MachineArchitecture::Arm),
            interface: interface.clone(),
            domain: rpc::Domain {
                id: None,
                name: "myforge.com".to_string(),
                created: None,
                updated: None,
                deleted: None,
            },
            machine: Some(rpc::forge::Machine {
                id: Some(rpc::MachineId {
                    id: "91609f10-c91d-470d-a260-6293ea0c0000".to_string(),
                }),
                created: None,
                updated: None,
                deployed: None,
                state: "ready".to_string(),
                events: Vec::new(),
                interfaces: vec![interface],
                discovery_info: None,
                machine_type: MachineType::Dpu as i32,
            }),
        };

        let runtime_config = RuntimeConfig {
            api_url: "https://127.0.0.1:8001".to_string(),
            pxe_url: "http://127.0.0.1:8080".to_string(),
            ntp_server: "127.0.0.2".to_string(),
        };

        let interface_id: uuid::Uuid = interface_id.parse().unwrap();

        let config = generate_forge_agent_config(interface_id, &machine, &runtime_config);

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
    }
}
