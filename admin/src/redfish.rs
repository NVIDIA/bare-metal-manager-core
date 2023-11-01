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
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::task::Task;
use libredfish::model::LinkStatus;
use libredfish::{Boot, EnabledDisabled, SystemPowerControl};
use libredfish::{
    Chassis, EthernetInterface, NetworkDeviceFunction, NetworkPort, Redfish, RedfishError,
};
use prettytable::{row, Table};

use super::cfg::carbide_options::RedfishCommand;
use crate::cfg::carbide_options::{DpuOperations, FwCommand, RedfishAction, ShowFw, ShowPort};

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
    let pool = libredfish::RedfishClientPool::builder().build()?;
    let redfish: Box<dyn Redfish> = pool.create_client(endpoint).await?;
    match action.command {
        BiosAttrs => {
            let bios = redfish.bios().await?;
            println!("{:#?}", bios);
        }
        BootHdd => {
            redfish.boot_first(Boot::HardDisk).await?;
        }
        BootPxe => {
            redfish.boot_first(Boot::Pxe).await?;
        }
        BootOnceHdd => {
            redfish.boot_once(Boot::HardDisk).await?;
        }
        BootOncePxe => {
            redfish.boot_once(Boot::Pxe).await?;
        }
        ClearPending => {
            redfish.clear_pending().await?;
        }
        ForgeSetup => {
            redfish.forge_setup().await?;
        }
        GetPowerState => {
            println!("{}", redfish.get_power_state().await?);
        }
        LockdownDisable => {
            redfish.lockdown(EnabledDisabled::Disabled).await?;
            println!("BIOS settings changes require system restart");
        }
        LockdownEnable => {
            redfish.lockdown(EnabledDisabled::Enabled).await?;
            println!("BIOS settings changes require system restart");
        }
        LockdownStatus => {
            println!("{}", redfish.lockdown_status().await?);
        }
        ForceOff => {
            redfish.power(SystemPowerControl::ForceOff).await?;
        }
        On => {
            redfish.power(SystemPowerControl::On).await?;
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
            for dev in redfish.pcie_devices().await? {
                let status = dev.status.unwrap();
                table.add_row(row![
                    dev.id.unwrap_or_default(),
                    dev.manufacturer.or(dev.gpu_vendor).unwrap_or_default(),
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
            let pending = redfish.pending().await?;
            println!("{:#?}", pending);
        }
        PowerMetrics => {
            println!("{:?}", redfish.get_power_metrics().await?);
        }
        ForceRestart => {
            redfish.power(SystemPowerControl::ForceRestart).await?;
        }
        GracefulRestart => {
            redfish.power(SystemPowerControl::GracefulRestart).await?;
        }
        SerialEnable => {
            redfish.setup_serial_console().await?;
            println!("BIOS settings changes require system restart");
        }
        SerialStatus => {
            println!("{}", redfish.serial_console_status().await?);
        }
        GracefulShutdown => {
            redfish.power(SystemPowerControl::GracefulShutdown).await?;
        }
        ThermalMetrics => {
            println!("{:?}", redfish.get_thermal_metrics().await?);
        }
        TpmReset => {
            redfish.clear_tpm().await?;
            println!("BIOS settings changes require system restart");
        }
        BmcReset => {
            redfish.bmc_reset().await?;
        }
        DisableSecureBoot => {
            redfish.disable_secure_boot().await?;
            println!("BIOS settings changes require system restart");
        }
        ChangeBmcPassword(bmc_password) => {
            redfish
                .change_password(&bmc_password.user, &bmc_password.new_password)
                .await?;
            println!("BIOS settings changes require system restart");
        }
        ChangeUefiPassword(uefi_password) => {
            redfish
                .change_uefi_password(&uefi_password.current_password, &uefi_password.new_password)
                .await?;
            println!("BIOS settings changes require system restart");
        }
        Dpu(dpu) => match dpu {
            DpuOperations::Firmware(fw) => match fw {
                FwCommand::Status => {
                    handle_fw_status(redfish).await?;
                }
                FwCommand::Update(fw_package) => {
                    let file_result = tokio::fs::File::open(fw_package.package).await;
                    if let Ok(file) = file_result {
                        redfish.update_firmware(file).await?;
                        println!("Track update progress using firmware status");
                    } else if let Err(err) = file_result {
                        eprintln!("Error opening file: {}", err);
                    }
                }
                FwCommand::Show(fw) => {
                    handle_fw_show(redfish, fw).await?;
                }
            },
            DpuOperations::Ports(ports) => {
                handle_port_show(redfish, ports).await?;
            }
        },
        GetChassisAll => {
            handle_get_chassis_all(redfish).await?;
        }
        GetBmcEthernetInterface => {
            handle_ethernet_interface_show(redfish).await?;
        }
    }
    Ok(())
}

pub async fn handle_fw_status(redfish: Box<dyn Redfish>) -> Result<(), RedfishError> {
    let tasks: Vec<String> = redfish.get_tasks().await?;
    let mut tasks_info: Vec<Task> = Vec::new();
    for task in tasks.iter() {
        if let Ok(t) = redfish.get_task(task).await {
            tasks_info.push(t);
        } else {
            println!("Task {} not found.", task);
        }
    }
    convert_tasks_to_nice_table(tasks_info).printstd();
    Ok(())
}

pub async fn handle_fw_show(redfish: Box<dyn Redfish>, args: ShowFw) -> Result<(), RedfishError> {
    if args.all || args.bmc || args.dpu_os || args.uefi {
        let f = FwFilter {
            only_bmc: args.bmc,
            only_dpu_os: args.dpu_os,
            only_uefi: args.uefi,
        };
        match show_all_fws(redfish, f).await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Error displaying firmware information: {}", e);
                Err(e)
            }
        }
    } else if let Some(fw_id) = args.fw {
        match redfish.get_firmware(&fw_id).await {
            Ok(firmware) => {
                convert_fws_to_nice_table(vec![firmware]).printstd();
                Ok(())
            }
            Err(err) => {
                eprintln!("Error fetching firmware '{fw_id}'");
                Err(err)
            }
        }
    } else {
        eprintln!(
            "Please specify at least one option (e.g., --all, --bmc, --dpu-os, --uefi, --fw)"
        );
        Ok(())
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct FwFilter {
    only_bmc: bool,
    only_dpu_os: bool,
    only_uefi: bool,
}

async fn show_all_fws(redfish: Box<dyn Redfish>, f: FwFilter) -> Result<(), RedfishError> {
    let fws: Vec<String> = redfish.get_software_inventories().await?;
    let mut fws_info: Vec<SoftwareInventory> = Vec::new();

    for fw in fws.iter() {
        if let Ok(firmware) = redfish.get_firmware(fw).await {
            fws_info.push(firmware);
        } else {
            println!("Firmware {} not found.", fw);
        }
    }

    if f.only_bmc {
        if !fws.contains(&"BMC_Firmware".to_string()) {
            println!("BMC FW is not found");
            return Err(RedfishError::NoContent);
        }
        fws_info.retain(|f| f.id.contains("BMC_Firmware"));
    }

    if f.only_dpu_os {
        if !fws.contains(&"DPU_OS".to_string()) {
            println!("DPU OS is not found");
            return Err(RedfishError::NoContent);
        }
        fws_info.retain(|f| f.id == *"DPU_OS");
    }

    if f.only_uefi {
        if !fws.contains(&"DPU_UEFI".to_string()) {
            println!("DPU UEFI is not found");
            return Err(RedfishError::NoContent);
        }
        fws_info.retain(|f| f.id == *"DPU_UEFI");
    }

    convert_fws_to_nice_table(fws_info).printstd();
    Ok(())
}

fn convert_fws_to_nice_table(fws: Vec<SoftwareInventory>) -> Box<Table> {
    let mut table = Table::new();
    table.add_row(row!["Id", "Version"]);
    for fw in fws {
        table.add_row(row![fw.id, fw.version.unwrap()]);
    }
    table.into()
}

fn convert_tasks_to_nice_table(tasks: Vec<Task>) -> Box<Table> {
    let mut table = Table::new();
    table.add_row(row![
        "Id",
        "State",
        "Status",
        "Percentage Completed (%)",
        "Messages"
    ]);
    for task in tasks {
        table.add_row(row![
            task.id,
            task.task_state
                .unwrap_or(libredfish::model::task::TaskState::Exception)
                .to_string(),
            task.task_status.clone().unwrap_or("None".to_string()),
            task.percent_complete.unwrap_or(0),
            task.messages
                .last()
                .map(|last_message| last_message.message.clone())
                .unwrap_or("No Message".to_string())
        ]);
    }
    table.into()
}

pub async fn handle_port_show(
    redfish: Box<dyn Redfish>,
    args: ShowPort,
) -> Result<(), RedfishError> {
    if !args.all && args.port.is_none() {
        eprintln!("Please specify at least one option (e.g., --all, --port)");
        return Ok(());
    }
    match show_all_ports(redfish).await {
        Ok((mut ports_info, netdev_funcs_info)) => {
            if let Some(port) = args.port {
                ports_info.retain(|f| *f.id.as_ref().unwrap() == port);
            }
            convert_ports_to_nice_table(ports_info, netdev_funcs_info).printstd();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn get_bluefield_chassis(redfish: &dyn Redfish) -> Result<String, RedfishError> {
    let chassis_vec: Vec<String> = redfish.get_chassis_all().await?;
    if let Some(bluefield_bmc) = chassis_vec
        .iter()
        .find(|&chassis| chassis.contains("Bluefield"))
    {
        Ok(bluefield_bmc.to_string())
    } else {
        eprintln!("Bluefield chassis was not found");
        Err(RedfishError::NoContent)
    }
}

async fn show_all_ports(
    redfish: Box<dyn Redfish>,
) -> Result<(Vec<NetworkPort>, Vec<NetworkDeviceFunction>), RedfishError> {
    let chassis_id = get_bluefield_chassis(&*redfish).await?;
    let ports: Vec<String> = redfish.get_ports(&chassis_id).await?;
    let mut ports_info: Vec<NetworkPort> = Vec::new();

    for p in ports.iter() {
        match redfish.get_port(&chassis_id, p).await {
            Ok(port) => {
                ports_info.push(port);
            }
            Err(err) => {
                eprintln!("Error fetching port {p}: {err}");
            }
        }
    }

    let netdev_funcs: Vec<String> = redfish.get_network_device_functions(&chassis_id).await?;
    let mut netdev_funcs_info: Vec<NetworkDeviceFunction> = Vec::new();

    for n in netdev_funcs.iter() {
        match redfish.get_network_device_function(&chassis_id, n).await {
            Ok(netdev) => {
                netdev_funcs_info.push(netdev);
            }
            Err(err) => {
                eprintln!("Error fetching network device {n}: {err}");
            }
        }
    }
    Ok((ports_info, netdev_funcs_info))
}

fn convert_ports_to_nice_table(
    ports: Vec<NetworkPort>,
    netdevs: Vec<NetworkDeviceFunction>,
) -> Box<Table> {
    let mut table = Table::new();
    table.add_row(row![
        "Id",
        "Link Status",
        "Type",
        "MAC Address",
        "MTU Size",
        "Speed (Gbps)"
    ]);

    for port in &ports {
        for netdev in &netdevs {
            if let (Some(port_id), Some(netdev_id)) = (&port.id, &netdev.id) {
                if netdev_id.contains(port_id) {
                    table.add_row(row![
                        port_id,
                        port.link_status
                            .as_ref()
                            .unwrap_or(&LinkStatus::NoLink)
                            .to_string(),
                        netdev
                            .net_dev_func_type
                            .as_ref()
                            .unwrap_or(&"None".to_string()),
                        netdev
                            .ethernet
                            .as_ref()
                            .and_then(|ethernet| ethernet.mac_address.as_ref())
                            .cloned()
                            .unwrap_or_else(|| "None".to_string()),
                        netdev
                            .ethernet
                            .as_ref()
                            .and_then(|ethernet| ethernet.mtu_size)
                            .unwrap_or(0),
                        port.current_speed_gbps.unwrap_or(0),
                    ]);
                }
            }
        }
    }

    table.into()
}

pub async fn handle_ethernet_interface_show(redfish: Box<dyn Redfish>) -> Result<(), RedfishError> {
    let eth_ifs: Vec<String> = redfish.get_ethernet_interfaces().await?;
    let mut eth_ifs_info: Vec<EthernetInterface> = Vec::new();

    for iface_id in eth_ifs.iter() {
        match redfish.get_ethernet_interface(iface_id).await {
            Ok(iface) => {
                eth_ifs_info.push(iface);
            }
            Err(err) => {
                eprintln!("Error fetching ethernet interface '{iface_id}': {err}");
            }
        }
    }
    convert_ethernet_interfaces_to_nice_table(eth_ifs_info).printstd();
    Ok(())
}

fn convert_ethernet_interfaces_to_nice_table(eth_ifs: Vec<EthernetInterface>) -> Box<Table> {
    let mut table = Table::new();
    table.add_row(row![
        "Id",
        "Link Status",
        "MAC Address",
        "MTU Size",
        "Speed (Mbps)",
    ]);

    for eth_if in &eth_ifs {
        table.add_row(row![
            eth_if.id.as_ref().unwrap_or(&"None".to_string()),
            eth_if
                .link_status
                .as_ref()
                .unwrap_or(&LinkStatus::NoLink)
                .to_string(),
            eth_if
                .mac_address
                .as_ref()
                .map_or("None".to_string(), |mac| mac.clone()),
            eth_if
                .mtu_size
                .map(|mtu| mtu.to_string())
                .unwrap_or("N/A".to_string()),
            eth_if
                .speed_mbps
                .map(|s| s.to_string())
                .unwrap_or("N/A".to_string()),
        ]);
    }
    table.into()
}

pub async fn handle_get_chassis_all(redfish: Box<dyn Redfish>) -> Result<(), RedfishError> {
    let chassis_vec: Vec<String> = redfish.get_chassis_all().await?;
    let mut chassis_info: Vec<Chassis> = Vec::new();

    for c in chassis_vec.iter() {
        match redfish.get_chassis(c).await {
            Ok(chassis) => {
                chassis_info.push(chassis);
            }
            Err(err) => {
                eprintln!("Error fetching chassis '{c}': {err}");
            }
        }
    }
    convert_chassis_to_nice_table(chassis_info).printstd();
    Ok(())
}

fn convert_chassis_to_nice_table(chassis_vec: Vec<Chassis>) -> Box<Table> {
    let mut table = Table::new();
    table.add_row(row!["Id", "Manufacturer", "Model",]);

    for chassis in &chassis_vec {
        table.add_row(row![
            chassis.id.as_ref().unwrap_or(&"None".to_string()),
            chassis.manufacturer.as_ref().unwrap_or(&"None".to_string()),
            chassis.model.as_ref().unwrap_or(&"None".to_string()),
        ]);
    }
    table.into()
}
