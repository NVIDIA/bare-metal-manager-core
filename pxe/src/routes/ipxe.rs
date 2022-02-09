use std::collections::HashMap;

use rocket::Route;
use rocket_dyn_templates::Template;

use crate::Machine;

#[derive(serde::Serialize)]
pub struct BootInstructionGenerator {
    pub kernel: String,
    pub initrd: String,
    pub command_line: String,
}

#[derive(serde::Serialize)]
pub struct IpxeScript<'a> {
    pub content: &'a str,
}

impl From<BootInstructionGenerator> for String {
    fn from(b: BootInstructionGenerator) -> Self {
        format!(
            r#"
kernel {} initrd=initrd.img {} ||
imgfetch --name initrd.img {} ||
boot ||
"#,
            b.kernel, b.command_line, b.initrd
        )
    }
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    Template::render("whoami", &machine)
}

#[get("/boot")]
pub async fn boot(machine: Machine) -> Template {
    let instructions = BootInstructionGenerator {
        kernel: "http://${next-server}:8000/public/blobs/internal/x86_64/carbide.efi".to_string(),
        initrd: "http://${next-server}:8000/public/blobs/internal/x86_64/carbide.root".to_string(),
        command_line: format!("url=http://${{next-server}}:8000/public/blobs/ubuntu-21.10-live-server-amd64.iso ip=dhcp autoinstall ds=nocloud-net;s=http://${{next-server}}:8000/api/v0/cloud-init/{}/", machine.0.id.unwrap()),
    };

    let mut context = HashMap::new();
    context.insert("ipxe", String::from(instructions));

    Template::render("pxe", &context)
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
