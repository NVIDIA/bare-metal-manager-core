use crate::{Machine, RuntimeConfig};
use rocket::routes;
use rocket::Route;
use rocket_dyn_templates::Template;
use std::collections::HashMap;

#[allow(unused_variables)] // The uuid is in the route so we cant prefix it w an underbar
#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine, config: RuntimeConfig) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("mac_address".to_string(), machine.interface.mac_address);
    context.insert("interface_id".to_string(), uuid.to_string());
    context.insert("api_url".to_string(), config.api_url);
    context.insert("pxe_url".to_string(), config.pxe_url);
    Template::render("user-data", &context)
}

#[allow(unused_variables)] // The uuid is in the route so we cant prefix it w an underbar
#[get("/<uuid>/meta-data")]
pub async fn meta_data(uuid: uuid::Uuid) -> Template {
    let context: HashMap<String, String> = HashMap::new();
    Template::render("printcontext", &context)
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data]
}
