#[macro_use]
extern crate rocket;

mod routes;

use rocket::fs::{relative, FileServer};
use rocket_dyn_templates::Template;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket::build()
        .mount("/api/v0/pxe", routes::ipxe::routes())
        .mount("/api/v0/cloud-init", routes::cloud_init::routes())
        .mount("/public", FileServer::from(relative!("static")))
        .attach(Template::fairing())
        .ignite()
        .await?
        .launch()
        .await
}
