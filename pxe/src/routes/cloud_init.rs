use crate::Machine;
use rocket::routes;
use rocket::Route;
use rocket_dyn_templates::Template;
use std::collections::HashMap;

#[allow(unused_variables)] // The uuid is in the route so we cant prefix it w an underbar
#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine) -> String {
    let mut context = tera::Context::new();
    context.insert("machine", &machine.interface);

    tera::Tera::one_off("", &context, false).unwrap()
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
