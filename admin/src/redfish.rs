/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use color_eyre::eyre::eyre;
use libredfish::{Boot, EnabledDisabled, SystemPowerControl};
use prettytable::{row, Table};

use super::cfg::carbide_options::RedfishCommand;
use crate::cfg::carbide_options::RedfishAction;

pub async fn action(action: RedfishAction) -> color_eyre::Result<()> {
    let endpoint = libredfish::Endpoint {
        host: match action.address {
            Some(a) => a,
            None => {
                return Err(eyre!("Missing --address"));
            }
        },
        user: action.username,
        password: action.password,
        ..Default::default()
    };
    use RedfishCommand::*;
    tokio::task::spawn_blocking(move || -> Result<(), libredfish::RedfishError> {
        let pool = libredfish::RedfishClientPool::builder().build()?;
        let redfish = pool.create_client(endpoint)?;
        match action.command {
            BiosAttrs => {
                let bios = redfish.bios()?;
                println!("{:#?}", bios);
            }
            BootHdd => {
                redfish.boot_first(Boot::HardDisk)?;
            }
            BootPxe => {
                redfish.boot_first(Boot::Pxe)?;
            }
            BootOnceHdd => {
                redfish.boot_once(Boot::HardDisk)?;
            }
            BootOncePxe => {
                redfish.boot_once(Boot::Pxe)?;
            }
            ClearPending => {
                redfish.clear_pending()?;
            }
            ForgeSetup => {
                redfish.forge_setup()?;
            }
            GetPowerState => {
                println!("{}", redfish.get_power_state()?);
            }
            LockdownDisable => {
                redfish.lockdown(EnabledDisabled::Disabled)?;
                println!("BIOS settings changes require system restart");
            }
            LockdownEnable => {
                redfish.lockdown(EnabledDisabled::Enabled)?;
                println!("BIOS settings changes require system restart");
            }
            LockdownStatus => {
                println!("{}", redfish.lockdown_status()?);
            }
            ForceOff => {
                redfish.power(SystemPowerControl::ForceOff)?;
            }
            On => {
                redfish.power(SystemPowerControl::On)?;
            }
            PcieDevices => {
                let mut table = Table::new();
                table.set_titles(row![
                    "ID",
                    "Manufacturer",
                    "Name",
                    "Firmware version",
                    "Part",
                    "Serial",
                    "Status",
                ]);
                for dev in redfish.pcie_devices()? {
                    let status = dev.status.unwrap();
                    table.add_row(row![
                        dev.id.unwrap_or_default(),
                        dev.manufacturer.unwrap(),
                        dev.name.unwrap_or_default(),
                        dev.firmware_version.unwrap_or_default(),
                        dev.part_number.unwrap_or_default(),
                        dev.serial_number.unwrap_or_default(),
                        format!("{} {}", status.health, status.state),
                    ]);
                }
                table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                table.printstd();
            }
            Pending => {
                let pending = redfish.pending()?;
                println!("{:#?}", pending);
            }
            ForceRestart => {
                redfish.power(SystemPowerControl::ForceRestart)?;
            }
            GracefulRestart => {
                redfish.power(SystemPowerControl::GracefulRestart)?;
            }
            SerialEnable => {
                redfish.setup_serial_console()?;
                println!("BIOS settings changes require system restart");
            }
            SerialStatus => {
                println!("{}", redfish.serial_console_status()?);
            }
            GracefulShutdown => {
                redfish.power(SystemPowerControl::GracefulShutdown)?;
            }
            TpmReset => {
                redfish.clear_tpm()?;
                println!("BIOS settings changes require system restart");
            }
        }
        Ok(())
    })
    .await??;
    Ok(())
}
