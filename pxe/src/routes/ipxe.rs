/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::fmt::Display;

use ::rpc::forge as rpc;
use rocket::{get, routes, Route};
use rocket_dyn_templates::Template;

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
    Template::render("whoami", machine)
}

fn generate_error_template<D1, D2>(error_str: D1, error_code: D2) -> Template
where
    D1: Display,
    D2: Display,
{
    let err = format!(
        r#"
echo {error_str} ||
exit {error_code} ||
"#,
    );
    let mut context = HashMap::new();
    context.insert("error".to_string(), err);
    Template::render("error", &context)
}

pub enum PxeErrorCode {
    InterfaceNotFound = 103,
    CouldNotDecodeUUID = 104,
    ArchitectureNotFound = 105,
}

#[get("/boot")]
pub async fn boot(contents: Machine, config: RuntimeConfig) -> Result<Template, Template> {
    let machine_interface_id = contents
        .interface
        .id
        .ok_or_else(|| {
            generate_error_template(
                "Interface not found".to_string(),
                PxeErrorCode::InterfaceNotFound as isize,
            )
        })
        .and_then(|uuid| {
            uuid::Uuid::try_from(uuid).map_err(|err| {
                generate_error_template(
                    format!("Could not decode uuid: {err}"),
                    PxeErrorCode::CouldNotDecodeUUID as isize,
                )
            })
        })?;
    let arch = contents.architecture.ok_or_else(|| {
        generate_error_template(
            "Architecture not found".to_string(),
            PxeErrorCode::ArchitectureNotFound as isize,
        )
    })?;

    let mut context = HashMap::new();
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert("pxe_url".to_string(), config.pxe_url.clone());

    let instructions = match contents.machine {
        None => boot_forge_host_image(arch, machine_interface_id, config),
        Some(m) => determine_boot_from_state(m, machine_interface_id, config, arch).await,
    };

    context.insert("ipxe".to_string(), instructions);

    Ok(Template::render("pxe", &context))
}

// TODO: Move this whole logic to API. A change in display value of state can cause iPXE to break.
// Also multiple states include substates. This can not be represented with String correctly.
async fn determine_boot_from_state(
    machine: rpc::Machine,
    machine_interface_id: uuid::Uuid,
    config: RuntimeConfig,
    arch: rpc::MachineArchitecture,
) -> String {
    let state = machine.state.to_lowercase();

    //TODO: This all logic should move to api in get_pxe_instructions call.
    if state == "ready" || state.starts_with("host/") || state.starts_with("waitingforcleanup/") {
        match arch {
            // The DPU needs an error code to force boot into the OS
            rpc::MachineArchitecture::Arm => "exit 1".to_string(),
            // X86 does not install OS in disk. It boots fresh everytime with carbide.efi.
            rpc::MachineArchitecture::X86 => {
                boot_forge_host_image(arch, machine_interface_id, config)
            }
        }
    } else if state.starts_with("assigned") {
        boot_tenant_image(machine, config).await
    } else {
        // any unrecognized state will cause ipxe to stop working with this message
        format!(
            r#"
echo could not continue boot due to invalid status - {} ||
sleep 5 ||
exit ||
"#,
            state
        )
    }
}

async fn boot_tenant_image(machine: rpc::Machine, config: RuntimeConfig) -> String {
    let machine_id = match machine.id {
        Some(id) => id,
        //TODO: Need a better way to deal with missing id.
        None => return "Machine ID is invalid".to_string(),
    };

    RpcContext::get_pxe_instructions(
        machine_id,
        config.api_url.clone(),
        config.forge_root_ca_path.clone(),
    )
    .await
    .unwrap_or_else(|err| {
        eprintln!("{}", err);
        format!(
            r#"
echo Failed to fetch custome_ipxe: {} ||
exit 101 ||
"#,
            err
        )
    })
}

// Boot host with our discovery and reset image
fn boot_forge_host_image(
    arch: rpc::MachineArchitecture,
    machine_interface_id: uuid::Uuid,
    config: RuntimeConfig,
) -> String {
    match arch {
        rpc::MachineArchitecture::Arm => {
            String::from(
                InstructionGenerator::Arm {
                    kernel: "${base-url}/internal/aarch64/carbide.efi".to_string(),
                    command_line: format!("console=tty0 console=ttyS0 console=ttyAMA0 console=hvc0 ip=dhcp cli_cmd=auto-detect bfnet=oob_net0:dhcp bfks=${{cloudinit-url}}/user-data machine_id={uuid} server_uri={api_url} ", uuid = machine_interface_id, api_url = config.api_url),
                    initrd: "${base-url}/internal/aarch64/carbide.root".to_string(),
            })
        }
        rpc::MachineArchitecture::X86 => {
            String::from( InstructionGenerator::X86 {
                    kernel: "${base-url}/internal/x86_64/carbide.efi".to_string(),
                    command_line: format!("root=live:${{base-url}}/internal/x86_64/carbide.root console=tty0 console=ttyS0 ip=dhcp cli_cmd=auto-detect machine_id={uuid} server_uri={api_url} ", uuid = machine_interface_id, api_url = config.api_url),
            })
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
