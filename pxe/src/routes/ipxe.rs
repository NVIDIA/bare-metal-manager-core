use std::collections::HashMap;

use rocket::{get, routes, Route};
use rocket_dyn_templates::Template;

use rpc::forge::v0 as rpc;

use crate::{Machine, RuntimeConfig};

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
        println!("Output of the generation - {:?}", output);
        output
    }
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    Template::render("whoami", &machine)
}

#[get("/boot")]
pub async fn boot(contents: Machine, config: RuntimeConfig) -> Template {
    let instructions = match contents.machine {
        None => boot_into_discovery(contents.architecture, contents.interface, config),
        Some(m) => determine_boot_from_state(m, contents.interface, config),
    };

    let mut context = HashMap::new();
    context.insert("ipxe", instructions);

    Template::render("pxe", &context)
}

fn determine_boot_from_state(
    machine: rpc::Machine,
    _interface: rpc::MachineInterface,
    _config: RuntimeConfig,
) -> String {
    match machine.state.as_str() {
        // The DPU needs an error code to force boot into the OS
        "new" => "exit 1".to_string(),
        "assigned" => boot_into_netbootxyz(),
        // any unrecognized state will cause ipxe to stop working with this message
        invalid_status => format!(
            r#"
echo could not continue boot due to invalid status - {} ||
sleep 5 ||
exit ||
"#,
            invalid_status
        )
        ,
    }
}

fn boot_into_netbootxyz() -> String {
    r#"
chain --autofree https://boot.netboot.xyz
"#
    .to_string()
}

fn boot_into_discovery(
    arch: rpc::MachineArchitecture,
    interface: rpc::MachineInterface,
    config: RuntimeConfig,
) -> String {
    let uuid = interface.id.unwrap();
    match arch {
        rpc::MachineArchitecture::Arm => {
            String::from(BootInstructionGenerator {
                kernel: format!("{pxe_url}/public/blobs/internal/aarch64/carbide.efi", pxe_url = config.pxe_url),
                initrd: format!("{pxe_url}/public/blobs/internal/aarch64/carbide.root", pxe_url = config.pxe_url),
                command_line: format!("root=live:{pxe_url}/public/blobs/internal/x86_64/carbide.root console=tty0 console=ttyS0 console=ttyAMA0 console=hvc0 ip=dhcp cli_cmd=discovery machine_id={uuid} bfnet=oob_net0:dhcp bfks={pxe_url}/api/v0/cloud-init/{uuid}/user-data pxe_uri={pxe_url} server_uri={api_url} ", pxe_url = config.pxe_url, uuid = uuid, api_url = config.api_url),
            })
        }
        rpc::MachineArchitecture::X86 => {
            String::from(BootInstructionGenerator {
                kernel: format!("{pxe_url}/public/blobs/internal/x86_64/carbide.efi", pxe_url = config.pxe_url),
                initrd: format!("{pxe_url}/public/blobs/internal/x86_64/carbide.root", pxe_url = config.pxe_url),
                command_line: format!("root=live:{pxe_url}/public/blobs/internal/x86_64/carbide.root console=tty0 console=ttyS0 ip=dhcp cli_cmd=discovery machine_id={uuid} bfnet=oob_net0:dhcp bfks={pxe_url}/api/v0/cloud-init/{uuid}/user-data pxe_uri={pxe_url} server_uri={api_url} ", pxe_url = config.pxe_url, uuid = uuid, api_url = config.api_url),
            })
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
