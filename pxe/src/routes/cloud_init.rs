use std::collections::HashMap;

use rocket::get;
use rocket::routes;
use rocket::serde::uuid;
use rocket::Route;
use rocket_dyn_templates::Template;

use crate::{Machine, RuntimeConfig};

#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine, config: RuntimeConfig) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine.interface.mac_address);
    context.insert("hostname".to_string(), machine.interface.hostname);
    context.insert("interface_id".to_string(), uuid.to_string());
    context.insert("api_url".to_string(), config.api_url);
    context.insert("pxe_url".to_string(), config.pxe_url);
    context.insert("ntp_server".to_string(), config.ntp_server);
    Template::render("user-data", &context)
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
