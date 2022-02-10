use crate::Machine;
use rocket::Route;
use rocket_dyn_templates::Template;
use std::collections::HashMap;

#[get("/<uuid>/user-data")]
pub async fn user_data(uuid: uuid::Uuid, machine: Machine) -> String {
    let mut context = tera::Context::new();
    context.insert("machine", &machine.0);

    tera::Tera::one_off("", &context, false).unwrap()
}

#[get("/<uuid>/meta-data")]
pub async fn meta_data(uuid: uuid::Uuid) -> Template {
    let context: HashMap<String, String> = HashMap::new();
    Template::render("printcontext", &context)
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data]
}
