/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    uuid: uuid::Uuid,
    machine: Machine,
    config: RuntimeConfig,
) -> (String, HashMap<String, String>) {
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine.interface.mac_address);
    context.insert(
        "hostname".to_string(),
        format!("{}.{}", machine.interface.hostname, machine.domain.name),
    );
    context.insert("interface_id".to_string(), uuid.to_string());
    context.insert("api_url".to_string(), config.api_url);
    context.insert("pxe_url".to_string(), config.pxe_url);
    context.insert("ntp_server".to_string(), config.ntp_server);
    ("user-data".to_string(), context)
}

#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine, config: RuntimeConfig) -> Template {
    let (template, context) = match machine.machine.as_ref() {
        Some(rpc_machine) if rpc_machine.state == "assigned" => {
            user_data_handler_in_assigned(machine, config).await
        }

        _ => user_data_handler(uuid, machine, config).await,
    };
    Template::render(template, &context)
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
