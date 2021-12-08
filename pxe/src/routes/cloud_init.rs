use crate::Machine;
use rocket::{Route, State};
use rocket_dyn_templates::Template;
use rpc::v0::carbide_client::CarbideClient;
use std::collections::HashMap;
use tonic::transport::Channel;

#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine) -> Template {
    Template::render("user-data", &machine)
}

#[get("/<uuid>/meta-data")]
pub async fn meta_data(uuid: uuid::Uuid) -> Template {
    let context: HashMap<String, String> = HashMap::new();

    Template::render("printcontext", &context)
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data]
}
