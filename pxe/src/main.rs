#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

mod routes;

use rocket_dyn_templates::Template;

use rpc::v0 as rpc;

use crate::rpc::carbide_client::CarbideClient;
use crate::rpc::{MachineQuery, MachineState};

#[derive(serde::Serialize)]
pub struct BootInstructionGenerator<'a> {
    pub hostname: &'a str,
    pub kernel: String,
    pub initrd: String,
    pub command_line: String,
    pub state: &'a str,
}

#[get("/")]
async fn entrypoint() -> Template {
    let mut client = CarbideClient::connect("https://[::1]:1079").await.unwrap();
    let request = tonic::Request::new(rpc::MachineQuery {
        id: None,
        fqdn: "".to_string(),
    });
    let response = client.find_machines(request).await.unwrap();

    let machine = &response.into_inner().machines[0];
    let context = BootInstructionGenerator {
        hostname: &machine.fqdn,
        kernel: "vmlinuz".to_string(),
        initrd: "initrd".to_string(),
        state: &machine.state.as_ref().unwrap().state,
        command_line: "console=ttyS0,115200,8n1".to_string(),
    };

    println!("{:#?}", serde_json::to_string(&context));

    Template::render("entrypoint", &context)
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket::build()
        .mount("/api/v0/entrypoint", routes![entrypoint])
        .attach(Template::fairing())
        .ignite()
        .await?
        .launch()
        .await
}
