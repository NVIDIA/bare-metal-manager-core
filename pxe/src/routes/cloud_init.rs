use rocket::Route;
use rocket_dyn_templates::Template;
use std::collections::HashMap;

#[get("/user-data")]
pub async fn user_data() -> Template {
    let context: HashMap<String, String> = HashMap::new();

    Template::render("printcontext", &context)
}

#[get("/meta-data")]
pub async fn meta_data() -> Template {
    let context: HashMap<String, String> = HashMap::new();

    Template::render("printcontext", &context)
}

pub fn routes() -> Vec<Route> {
    routes![user_data, meta_data]
}
