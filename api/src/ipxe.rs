pub use ::rpc::forge as rpc;
use sqlx::{Postgres, Transaction};

use crate::db::machine_boot_override::MachineBootOverride;
use crate::model::machine::ReprovisionState;
use crate::{
    db::{
        instance::Instance,
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
    },
    model::machine::{InstanceState, MachineState, ManagedHostState},
    CarbideError,
};

pub struct PxeInstructions;

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

impl InstructionGenerator {
    fn serialize_pxe_instructions(&self) -> String {
        match self {
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
                output
            }
        }
    }
}

impl PxeInstructions {
    fn get_pxe_instruction_for_arch(
        arch: rpc::MachineArchitecture,
        machine_interface_id: uuid::Uuid,
        mac_address: String,
        console: &str,
    ) -> String {
        match arch {
            rpc::MachineArchitecture::Arm => {
                    InstructionGenerator::Arm {
                        kernel: "${base-url}/internal/aarch64/carbide.efi".to_string(),
                        command_line: format!("console=tty0 console=ttyS0,115200 console=ttyAMA0 console=hvc0 ip=dhcp cli_cmd=auto-detect bfnet=oob_net0:dhcp bfks=${{cloudinit-url}}/user-data machine_id={uuid} server_uri=[api_url] ", uuid = machine_interface_id),
                        initrd: "${base-url}/internal/aarch64/carbide.root".to_string(),
                }
            }
            rpc::MachineArchitecture::X86 => {
                InstructionGenerator::X86 {
                        kernel: "${base-url}/internal/x86_64/carbide.efi".to_string(),
                        command_line: format!("root=live:${{base-url}}/internal/x86_64/carbide.root console=tty0 console={tty},115200 ifname=bootnic:{mac} ip=bootnic:dhcp pci=realloc=off cli_cmd=auto-detect machine_id={uuid} server_uri=[api_url] ", uuid = machine_interface_id, mac = mac_address, tty = console),
                }
            }
        }.serialize_pxe_instructions()
    }

    pub async fn get_pxe_instructions(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: uuid::Uuid,
        arch: rpc::MachineArchitecture,
    ) -> Result<String, CarbideError> {
        let error_instructions = |x: &ManagedHostState| -> String {
            format!(
                r#"
echo could not continue boot due to invalid state - {} ||
sleep 5 ||
exit ||
"#,
                x
            )
        };

        let mut console = "ttyS0";
        let interface = MachineInterface::find_one(txn, interface_id).await?;

        // This custom pxe is different from a customer instance of pxe. It is more for testing one off
        // changes until a real dev env is established and we can just override our existing code to test
        // It is possible for the pxe to be null if we are only trying to test the user data, and this will
        // follow the same code path and retrieve the non customer pxe
        if let Some(machine_boot_override) =
            MachineBootOverride::find_optional(txn, interface_id).await?
        {
            if let Some(custom_pxe) = machine_boot_override.custom_pxe {
                return Ok(custom_pxe);
            }
        }

        let mac = interface.mac_address.to_string();
        let machine_id = match interface.machine_id {
            None => {
                return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                    arch,
                    interface_id,
                    mac,
                    console,
                ));
            }
            Some(machine_id) => machine_id,
        };

        let machine = Machine::find_one(txn, &machine_id, MachineSearchConfig::default())
            .await
            .map_err(|e| {
                CarbideError::InvalidArgument(format!("Get machine failed, Error: {}", e))
            })?
            .ok_or(CarbideError::InvalidArgument(
                "Invalid machine id. Not found in db.".to_string(),
            ))?;

        // DPUs need to boot twice during initial discovery. Both reboots require
        // that the DPU gets pxe instructions.
        //
        // The first boot (before it even exists in the DB) enables firmware update
        // but will not install HBN.  This is handled above when no machine is found.
        //
        // The second boot enables HBN.  This is handled here when the DPU is
        // waiting for the network install
        if machine.is_dpu() {
            if let Some(reprov_state) = &machine.current_state().as_reprovision_state() {
                if matches!(
                    reprov_state,
                    ReprovisionState::FirmwareUpgrade | ReprovisionState::WaitingForNetworkInstall
                ) {
                    return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                        arch,
                        interface_id,
                        mac,
                        console,
                    ));
                }
            }

            match &machine.current_state() {
                ManagedHostState::DPUNotReady {
                    machine_state: MachineState::WaitingForNetworkInstall,
                } => {
                    return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                        arch,
                        interface_id,
                        mac,
                        console,
                    ));
                }
                _ => {
                    return Ok("exit".to_string());
                }
            }
        }

        if let Some(hardware_info) = machine.hardware_info() {
            if let Some(dmi_info) = hardware_info.dmi_data.as_ref() {
                if dmi_info.sys_vendor == "Lenovo" {
                    console = "ttyS1";
                }
            }
        }

        let pxe_script = match &machine.current_state() {
            ManagedHostState::Ready
            | ManagedHostState::HostNotReady { .. }
            | ManagedHostState::WaitingForCleanup { .. } => {
                Self::get_pxe_instruction_for_arch(arch, interface_id, mac, console)
            }
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::Ready => {
                    let instance = Instance::find_by_machine_id(txn, &machine_id)
                        .await
                        .map_err(CarbideError::from)?
                        .ok_or(CarbideError::NotFoundError {
                            kind: "machine",
                            id: machine_id.to_string(),
                        })?;

                    if instance.use_custom_pxe_on_boot {
                        // We don't have to reset the flag for `always_boot_with_custom_ipxe`, since
                        // it's note used in this case
                        Instance::use_custom_ipxe_on_next_boot(&machine_id, false, txn)
                            .await
                            .map_err(CarbideError::from)?;
                    }

                    if instance.tenant_config.always_boot_with_custom_ipxe
                        || instance.use_custom_pxe_on_boot
                    {
                        instance.tenant_config.custom_ipxe
                    } else {
                        "exit".to_string()
                    }
                }
                InstanceState::BootingWithDiscoveryImage { .. } => {
                    PxeInstructions::get_pxe_instruction_for_arch(arch, interface_id, mac, console)
                }

                _ => error_instructions(&machine.current_state()),
            },
            x => error_instructions(x),
        };

        Ok(pxe_script)
    }
}
