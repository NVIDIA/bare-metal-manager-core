use rocket::Route;
use rocket_dyn_templates::Template;

use crate::Machine;
use std::collections::HashMap;

#[derive(serde::Serialize)]
pub struct BootInstructionGenerator<'a> {
    pub hostname: &'a str,
    pub kernel: String,
    pub initrd: String,
    pub command_line: String,
    pub state: &'a str,
}

#[derive(serde::Serialize)]
pub struct IpxeScript<'a> {
    pub content: &'a str,
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    let mut context = HashMap::new();

    context.insert("machine", format!("{:#?}", machine));

    Template::render("printcontext", &context)
}

#[get("/boot")]
pub async fn boot(machine: Machine) -> Template {
    let context = BootInstructionGenerator {
        hostname: &machine.0.fqdn,
        kernel: "".to_string(),
        initrd: "initrd".to_string(),
        state: &machine.0.state.as_ref().unwrap().state,
        command_line: "console=ttyS0,115200,8n1".to_string(),
    };

    Template::render("pxe", &context)
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
