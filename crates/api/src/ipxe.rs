/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use ::rpc::forge as rpc;
use carbide_uuid::machine::{MachineId, MachineInterfaceId, MachineType};
use db::{self};
use mac_address::MacAddress;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    DpuInitState, FailureCause, FailureDetails, InstanceState, ManagedHostState, MeasuringState,
    ReprovisionState, ValidationState,
};
use model::pxe::PxeInstructionRequest;
use sqlx::PgConnection;

use crate::CarbideError;

const QCOW_IMAGER_IPXE: &str =
    "chain ${base-url}/internal/x86_64/qcow-imager.efi loglevel=7 console=tty0 pci=realloc=off ";

pub struct PxeInstructions;

#[derive(serde::Serialize)]
pub struct InstructionGenerator {
    kernel: String,
    command_line: String,
    initrd: Option<String>,
}

impl InstructionGenerator {
    fn serialize_pxe_instructions(&self) -> String {
        match &self.initrd {
            Some(initrd) => {
                format!(
                    r#"
kernel {} initrd=initrd.img {} ||
imgfetch --name initrd.img {} ||
boot ||
"#,
                    self.kernel, self.command_line, initrd
                )
            }
            None => {
                let output = format!(
                    r#"
kernel {} {} ||
boot ||
"#,
                    self.kernel, self.command_line
                );
                output
            }
        }
    }
}

impl PxeInstructions {
    fn get_pxe_instruction_for_arch(
        arch: rpc::MachineArchitecture,
        machine_interface_id: MachineInterfaceId,
        mac_address: MacAddress,
        console: &str,
        machine_type: MachineType,
    ) -> String {
        tracing::info!(
            "machine_type: {machine_type}; machine interface ID: {machine_interface_id}; mac address: {mac_address}"
        );
        match arch {
            rpc::MachineArchitecture::Arm => {
                if machine_type == MachineType::Host || machine_type == MachineType::PredictedHost {
                    InstructionGenerator {
                        kernel: "${base-url}/internal/aarch64/scout.efi".to_string(),
                        command_line: format!("mac={mac_address} console=tty0 console={console},115200 pci=realloc=off iommu=off cli_cmd=auto-detect machine_id={machine_interface_id} server_uri=[api_url] "),
                        initrd: None,
                    }
                }
                else {
                     // For the DPUs, bfks => BlueField Kick Start script
                     InstructionGenerator {
                        kernel: "${base-url}/internal/aarch64/carbide.efi".to_string(),
                        command_line: format!("console=tty0 console=ttyS0,115200 console=ttyAMA0 console=hvc0 ip=dhcp cli_cmd=auto-detect bfnet=oob_net0:dhcp bfks=${{cloudinit-url}}/user-data machine_id={machine_interface_id} server_uri=[api_url] "),
                        initrd: Some("${base-url}/internal/aarch64/carbide.root".to_string()),
                    }
                }
            }
            rpc::MachineArchitecture::X86 => {
                InstructionGenerator {
                    kernel: "${base-url}/internal/x86_64/scout.efi".to_string(),
                    command_line: format!("mac={mac_address} console=tty0 console={console},115200 pci=realloc=off iommu=off cli_cmd=auto-detect machine_id={machine_interface_id} server_uri=[api_url] "),
                    initrd: None,
                }
            }
        }.serialize_pxe_instructions()
    }

    pub async fn get_pxe_instructions(
        txn: &mut PgConnection,
        target: PxeInstructionRequest,
    ) -> Result<String, CarbideError> {
        let error_instructions = |machine_id: MachineId,
                                  interface_id: MachineInterfaceId,
                                  state: &ManagedHostState|
         -> String {
            format!(
                r#"
echo Machine ID: {machine_id}
echo Interface ID: {interface_id}
echo Current state: {state}
echo Could not continue boot due to invalid state ||
sleep 5 ||
exit ||
"#
            )
        };

        let exit_instructions = |machine_id: MachineId,
                                 interface_id: MachineInterfaceId,
                                 state: &ManagedHostState|
         -> String {
            format!(
                r#"
echo Machine ID: {machine_id}
echo Interface ID: {interface_id}
echo Current state: {state}
echo This state assumes an OS is provisioned and will exit into the OS in 5 seconds. To re-run iPXE instructions and OS installation, trigger a reboot request with flag rebootWithCustomIpxe/boot_with_custom_ipxe set. ||
sleep 5 ||
exit ||
"#
            )
        };

        static UNKNOWN_HOST_INSTRUCTIONS: &str = r#"
echo this is an unknown ARM host, not PXE booting ||
sleep 5 ||
exit ||
        "#;

        let mut console = "ttyS0";
        let interface = db::machine_interface::find_one(txn, target.interface_id).await?;

        // This custom pxe is different from a customer instance of pxe. It is more for testing one off
        // changes until a real dev env is established and we can just override our existing code to test
        // It is possible for the pxe to be null if we are only trying to test the user data, and this will
        // follow the same code path and retrieve the non customer pxe
        if let Some(machine_boot_override) =
            db::machine_boot_override::find_optional(txn, target.interface_id).await?
            && let Some(custom_pxe) = machine_boot_override.custom_pxe
        {
            return Ok(custom_pxe);
        }

        let Some(machine_id) = interface.machine_id else {
            // FORGE-7330: If site-explorer can't get the interface info from the bmc, then it won't associate the interface with a machine.
            // if the pxe request included the product and its a DPU, the machine record is not needed and we can just use the DPU type.
            if let Some(product) = target.product
                && product.to_ascii_lowercase().contains("bluefield")
            {
                if target.arch == rpc::MachineArchitecture::Arm {
                    return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                        target.arch,
                        target.interface_id,
                        interface.mac_address,
                        console,
                        MachineType::Dpu,
                    ));
                } else {
                    tracing::warn!(
                        "Unsupported DPU type. Product is '{}', but architecture is {:?}",
                        product,
                        target.arch,
                    )
                }
            };
            // We haven't minted a machine ID for this yet, so we don't know if it's a DPU or a
            // Host. We can't assume ARM = DPU, because there are zero-dpu ARM hosts. Heuristics we
            // use:
            // - If we don't have an exploration report for this MAC address, don't PXE boot at all
            // - If it's X86 and we have an exploration report, assume it's a Host.
            // - If it's ARM and we have an exploration report, check if the report is a bluefield
            //   model.
            let Some(endpoint) =
                db::explored_endpoints::find_by_mac_address(txn, interface.mac_address)
                    .await?
                    .into_iter()
                    .next()
            else {
                // This only happens if someone powered on a host manually before we ingested it,
                // which is unlikely but possible.
                tracing::info!(interface = ?interface, "Request for PXE instructions for unknown interface, skipping PXE boot");
                return Ok(UNKNOWN_HOST_INSTRUCTIONS.to_string());
            };

            return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                target.arch,
                target.interface_id,
                interface.mac_address,
                console,
                match target.arch {
                    rpc::MachineArchitecture::X86 => MachineType::PredictedHost,
                    rpc::MachineArchitecture::Arm => {
                        if endpoint.is_bluefield_model() {
                            MachineType::Dpu
                        } else {
                            MachineType::PredictedHost
                        }
                    }
                },
            ));
        };

        let machine = db::machine::find_one(txn, &machine_id, MachineSearchConfig::default())
            .await
            .map_err(|e| CarbideError::InvalidArgument(format!("Get machine failed, Error: {e}")))?
            .ok_or(CarbideError::InvalidArgument(
                "Invalid machine id. Not found in db.".to_string(),
            ))?;

        tracing::info!(machine_id = %machine.id, interface_id = %target.interface_id, state=%machine.current_state(), "Found existing machine for pxe instructions");
        // DPUs need to boot twice during initial discovery. Both reboots require
        // that the DPU gets pxe instructions.
        //
        // The first boot (before it even exists in the DB) enables firmware update
        // but will not install HBN.  This is handled above when no machine is found.
        //
        // The second boot enables HBN.  This is handled here when the DPU is
        // waiting for the network install
        if machine.is_dpu() {
            if let Some(reprov_state) = &machine.current_state().as_reprovision_state(&machine_id)
                && matches!(
                    reprov_state,
                    ReprovisionState::FirmwareUpgrade | ReprovisionState::WaitingForNetworkInstall
                )
            {
                return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                    target.arch,
                    target.interface_id,
                    interface.mac_address,
                    console,
                    machine.id.machine_type(),
                ));
            }

            match &machine.current_state() {
                ManagedHostState::DPUInit { dpu_states } => {
                    let Some(dpu_state) = dpu_states.states.get(&machine_id) else {
                        return Err(CarbideError::MissingDpu(machine_id));
                    };

                    match dpu_state {
                        DpuInitState::Init => {
                            return Ok(PxeInstructions::get_pxe_instruction_for_arch(
                                target.arch,
                                target.interface_id,
                                interface.mac_address,
                                console,
                                machine.id.machine_type(),
                            ));
                        }
                        _ => {
                            return Ok(exit_instructions(
                                machine_id,
                                target.interface_id,
                                machine.current_state(),
                            ));
                        }
                    }
                }
                _ => {
                    return Ok(exit_instructions(
                        machine_id,
                        target.interface_id,
                        machine.current_state(),
                    ));
                }
            }
        }

        if let Some(hardware_info) = machine.hardware_info.as_ref()
            && let Some(dmi_info) = hardware_info.dmi_data.as_ref()
            && (dmi_info.sys_vendor == "Lenovo" || dmi_info.sys_vendor == "Supermicro")
        {
            console = "ttyS1";
        }

        let pxe_script = match &machine.current_state() {
            ManagedHostState::Ready
            | ManagedHostState::HostInit { .. }
            | ManagedHostState::BomValidating { .. }
            | ManagedHostState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            }
            | ManagedHostState::Failed {
                details:
                    FailureDetails {
                        cause: FailureCause::Discovery { .. },
                        ..
                    },
                ..
            }
            | ManagedHostState::Failed {
                details:
                    FailureDetails {
                        cause: FailureCause::NVMECleanFailed { .. },
                        ..
                    },
                ..
            }
            | ManagedHostState::Failed {
                details:
                    FailureDetails {
                        cause: FailureCause::MachineValidation { .. },
                        ..
                    },
                ..
            }
            | ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation { .. },
            }
            | ManagedHostState::WaitingForCleanup { .. } => Self::get_pxe_instruction_for_arch(
                target.arch,
                target.interface_id,
                interface.mac_address,
                console,
                machine.id.machine_type(),
            ),
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::Ready => {
                    let instance = db::instance::find_by_machine_id(txn, &machine_id)
                        .await?
                        .ok_or(CarbideError::NotFoundError {
                            kind: "machine",
                            id: machine_id.to_string(),
                        })?;

                    if instance
                        .config
                        .os
                        .run_provisioning_instructions_on_every_boot
                        || instance.use_custom_pxe_on_boot
                    {
                        // For non-always-PXE instances, clear the use_custom_pxe_on_boot flag
                        // now that we're serving the script. Always-PXE instances don't use
                        // this flag (they rely on run_provisioning_instructions_on_every_boot).
                        if instance.use_custom_pxe_on_boot {
                            db::instance::use_custom_ipxe_on_next_boot(&machine_id, false, txn)
                                .await?;
                        }

                        match instance.config.os.variant {
                            model::os::OperatingSystemVariant::Ipxe(ipxe) => {
                                let mut tenant_ipxe = ipxe.ipxe_script;
                                let vendor_serial_console = format!(" console={console}");
                                if !tenant_ipxe.contains(&vendor_serial_console) {
                                    let idx = tenant_ipxe.find(" console=");
                                    if let Some(x) = idx {
                                        // insert correct serial console into custom ipxe before any other console=tty* specified
                                        tenant_ipxe.insert_str(x, &vendor_serial_console);
                                    } else {
                                        // this is a strange ipxe script with no console=tty defined, leave it as is
                                    }
                                }
                                tenant_ipxe
                            }
                            model::os::OperatingSystemVariant::OsImage(id) => {
                                let os_image = db::os_image::get(txn, id).await?;
                                if os_image.attributes.create_volume {
                                    // this is a block storage os image
                                    // boot will be via the block storage snapshot volume
                                    // no ipxe script for os imaging
                                    exit_instructions(
                                        machine_id,
                                        target.interface_id,
                                        machine.current_state(),
                                    )
                                } else {
                                    let mut qcow_imaging_ipxe = format!(
                                        "{} console={},115200 image_url={} image_sha={}",
                                        QCOW_IMAGER_IPXE,
                                        console,
                                        os_image.attributes.source_url,
                                        os_image.attributes.digest
                                    );
                                    if let Some(x) = os_image.attributes.auth_token {
                                        qcow_imaging_ipxe +=
                                            format!(" image_auth_token={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.auth_type {
                                        qcow_imaging_ipxe +=
                                            format!(" image_auth_type={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.rootfs_id {
                                        qcow_imaging_ipxe += format!(" rootfs_uuid={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.rootfs_label {
                                        qcow_imaging_ipxe += format!(" rootfs_label={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.boot_disk {
                                        qcow_imaging_ipxe += format!(" image_disk={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.bootfs_id {
                                        qcow_imaging_ipxe += format!(" bootfs_uuid={x}").as_str();
                                    }
                                    if let Some(x) = os_image.attributes.efifs_id {
                                        qcow_imaging_ipxe += format!(" efifs_uuid={x}").as_str();
                                    }
                                    if instance.config.os.user_data.is_some() {
                                        qcow_imaging_ipxe += " ds=nocloud-net;s=${cloudinit-url}";
                                    }
                                    qcow_imaging_ipxe += "\r\nboot";
                                    qcow_imaging_ipxe
                                }
                            }
                        }
                    } else {
                        exit_instructions(machine_id, target.interface_id, machine.current_state())
                    }
                }
                InstanceState::BootingWithDiscoveryImage { .. }
                | InstanceState::HostReprovision { .. } => {
                    PxeInstructions::get_pxe_instruction_for_arch(
                        target.arch,
                        target.interface_id,
                        interface.mac_address,
                        console,
                        machine.id.machine_type(),
                    )
                }

                _ => error_instructions(machine_id, target.interface_id, machine.current_state()),
            },
            x => error_instructions(machine_id, target.interface_id, x),
        };

        Ok(pxe_script)
    }
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;

    #[test]
    /// test_formatted_mac_for_instruction_generator makes sure the MAC address
    /// does what we want/expect as part of how we pass it to the instruction
    /// generator.
    fn test_formatted_mac_for_instruction_generator() {
        // also confirm lower -> upper while we're at it
        let mac_address: MacAddress = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!("AA:BB:CC:DD:EE:FF".to_string(), format!("{mac_address}"));
    }
}
