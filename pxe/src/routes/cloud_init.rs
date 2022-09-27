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
    let user_data = match machine.machine {
        Some(rpc_machine) => {
            match RpcContext::get_instance(rpc_machine.id.unwrap(), config.api_url.clone()).await {
                Ok(instance) => instance
                    .user_data
                    .unwrap_or_else(|| "User data is not available.".to_string()),
                Err(err) => {
                    eprintln!("{}", err);
                    format!("Failed to fetch user_data: {}", err)
                }
            }
        }
        None => "Failed to fetch machine_details.".to_string(),
    };

    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("user-data".to_string(), user_data);
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

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data]
}
