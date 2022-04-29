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
        let output = format!(
            r#"
kernel {} initrd=initrd.img {} ||
imgfetch --name initrd.img {} ||
boot ||
"#,
            b.kernel, b.command_line, b.initrd
        );
        println!("Output of the generation - {:?}", output.to_string());
        output
    }
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    Template::render("whoami", &machine)
}

#[get("/boot")]
pub async fn boot(machine: Machine) -> Template {
    let instructions = BootInstructionGenerator {
        kernel: "http://${next-server}:8080/public/blobs/internal/x86_64/carbide.efi".to_string(),
        initrd: "http://${next-server}:8080/public/blobs/internal/x86_64/carbide.root".to_string(),
        // TODO(baz): make sure this dhcp next_server envoy IP is removed
        command_line: format!("root=live:http://${{next-server}}:8080/public/blobs/internal/x86_64/carbide.root console=tty0 console=ttyS0 ip=dhcp machine_id={} server_uri={}", machine.0.id.unwrap(), "https://172.20.0.18:80"),
    };

    let mut context = HashMap::new();
    context.insert("ipxe", String::from(instructions));

    Template::render("pxe", &context)
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
