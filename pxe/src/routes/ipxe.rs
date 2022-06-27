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
pub async fn boot(contents: Machine) -> Template {
    let instructions = match contents.machine {
        None => boot_into_discovery(contents.interface),
        Some(m) => determine_boot_from_state(m, contents.interface),
    };

    let mut context = HashMap::new();
    context.insert("ipxe", instructions);

    Template::render("pxe", &context)
}

fn determine_boot_from_state(
    machine: rpc::v0::Machine,
    interface: rpc::v0::MachineInterface,
) -> String {
    match machine.state.as_str() {
        "new" => boot_into_discovery(interface),
        "assigned" => boot_into_netbootxyz(),
        // any unrecognized state will cause ipxe to stop working with this message
        s => format!(
            r#"
echo could not continue boot due to invalid status - {} ||
sleep 5 ||
exit ||
"#,
            s
        )
        .to_string(),
    }
}

fn boot_into_netbootxyz() -> String {
    r#"
chain --autofree https://boot.netboot.xyz
"#
    .to_string()
}

fn boot_into_discovery(interface: rpc::v0::MachineInterface) -> String {
    let instructions = BootInstructionGenerator {
        kernel: "http://${next-server}:8080/public/blobs/internal/x86_64/carbide.efi".to_string(),
        initrd: "http://${next-server}:8080/public/blobs/internal/x86_64/carbide.root".to_string(),
        command_line: format!("root=live:http://${{next-server}}:8080/public/blobs/internal/x86_64/carbide.root console=tty0 console=ttyS0 console=ttyAMA0 console=hvc0 ip=dhcp machine_id={} server_uri=https://${{next-server}}:80", interface.id.unwrap()),
    };
    String::from(instructions)
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
