use std::collections::HashMap;

use rocket::{get, routes, Route};
use rocket_dyn_templates::Template;

use ::rpc::forge as rpc;

use crate::machine_architecture::MachineArchitecture;
use crate::routes::RpcContext;
use crate::{Machine, RuntimeConfig};

#[derive(serde::Serialize)]
pub enum InstructionGenerator {
    X86 {
        kernel: String,
        command_line: String,
    },
    Arm {
        kernel: String,
        command_line: String,
        initrd: String,
    },
}

#[derive(serde::Serialize)]
pub struct IpxeScript<'a> {
    pub content: &'a str,
}

impl From<InstructionGenerator> for String {
    fn from(b: InstructionGenerator) -> Self {
        match b {
            InstructionGenerator::Arm {
                kernel,
                command_line,
                initrd,
            } => {
                let output = format!(
                    r#"
kernel {} initrd=initrd.img {} ||
imgfetch --name initrd.img {} ||
boot ||
"#,
                    kernel, command_line, initrd
                );
                println!("Output of the generation - {:?}", output);
                output
            }
            InstructionGenerator::X86 {
                kernel,
                command_line,
            } => {
                let output = format!(
                    r#"
kernel {} {} ||
boot ||
"#,
                    kernel, command_line
                );
                println!("Output of the generation - {:?}", output);
                output
            }
        }
    }
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    Template::render("whoami", &machine)
}

#[get("/boot")]
pub async fn boot(contents: Machine, config: RuntimeConfig) -> Template {
    let instructions = match contents.architecture {
        Some(arch) => match contents.machine {
            None => boot_into_discovery(arch, contents.interface, config),
            Some(m) => determine_boot_from_state(m, contents.interface, config).await,
        },
        None => r#"
echo Architecture was not specified ||
exit 102 ||
"#
        .to_string(),
    };

    let mut context = HashMap::new();
    context.insert("ipxe", instructions);

    Template::render("pxe", &context)
}

async fn determine_boot_from_state(
    machine: rpc::Machine,
    interface: rpc::MachineInterface,
    config: RuntimeConfig,
) -> String {
    match machine.state.as_str() {
        // The DPU needs an error code to force boot into the OS
        "ready" => "exit 1".to_string(),
        "reset" => boot_into_discovery(rpc::MachineArchitecture::X86, interface, config),
        "assigned" => boot_tenant_config(machine, config).await,
        // any unrecognized state will cause ipxe to stop working with this message
        invalid_status => format!(
            r#"
echo could not continue boot due to invalid status - {} ||
sleep 5 ||
exit ||
"#,
            invalid_status
        ),
    }
}

async fn boot_tenant_config(machine: rpc::Machine, config: RuntimeConfig) -> String {
    let machine_id = match machine.id {
        Some(id) => id,
        //TODO: Need a better way to deal with missing id.
        None => return "Machine ID is invalid".to_string(),
    };

    match RpcContext::get_instance(machine_id, config.api_url.clone()).await {
        Ok(instance) => instance.custom_ipxe,
        Err(err) => {
            eprintln!("{}", err);
            format!(
                r#"
echo Failed to fetch custome_ipxe: {} || 
exit 101 ||
"#,
                err
            )
        }
    }
}

fn boot_into_discovery(
    arch: rpc::MachineArchitecture,
    interface: rpc::MachineInterface,
    config: RuntimeConfig,
) -> String {
    let uuid = interface.id.unwrap();
    let build_arch = MachineArchitecture::from(arch);

    match arch {
        rpc::MachineArchitecture::Arm => {
            String::from(
                InstructionGenerator::Arm {
                    kernel: format!("{pxe_url}/public/blobs/internal/aarch64/carbide.efi", pxe_url = config.pxe_url),
                    command_line: format!("console=tty0 console=ttyS0 console=ttyAMA0 console=hvc0 ip=dhcp cli_cmd=discovery machine_id={uuid} bfnet=oob_net0:dhcp bfks={pxe_url}/api/v0/cloud-init/{uuid}/user-data?buildarch={build_arch} pxe_uri={pxe_url} server_uri={api_url} ", pxe_url = config.pxe_url, uuid = uuid, build_arch = build_arch, api_url = config.api_url),
                    initrd: format!("{pxe_url}/public/blobs/internal/aarch64/carbide.root", pxe_url = config.pxe_url),
            })
        }
        rpc::MachineArchitecture::X86 => {
            String::from( InstructionGenerator::X86 {
                    kernel: format!("{pxe_url}/public/blobs/internal/x86_64/carbide.efi", pxe_url = config.pxe_url),
                    command_line: format!("root=live:{pxe_url}/public/blobs/internal/x86_64/carbide.root console=tty0 console=ttyS0 ip=dhcp cli_cmd=discovery machine_id={uuid} bfnet=oob_net0:dhcp bfks={pxe_url}/api/v0/cloud-init/{uuid}/user-data?buildarch={build_arch} pxe_uri={pxe_url} server_uri={api_url} ", pxe_url = config.pxe_url, uuid = uuid, build_arch = build_arch, api_url = config.api_url),

            })
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
