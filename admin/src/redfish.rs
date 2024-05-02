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
use forge_secrets::credentials::Credentials;
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::task::Task;
use libredfish::model::LinkStatus;
use libredfish::{Boot, EnabledDisabled, RoleId, SystemPowerControl};
use libredfish::{
    Chassis, EthernetInterface, NetworkDeviceFunction, NetworkPort, Redfish, RedfishError,
};
use prettytable::{row, Table};
use tracing::warn;

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

    let proxy = std::env::var("http_proxy")
        .ok()
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("HTTP_PROXY").ok())
        .or_else(|| std::env::var("HTTPS_PROXY").ok());

    use RedfishCommand::*;
    let pool = libredfish::RedfishClientPool::builder()
        .proxy(proxy)
        .build()?;
    let redfish: Box<dyn Redfish> = match action.command.clone() {
        ChangeBmcPassword(_) => pool.create_standard_client(endpoint)?,
        _ => pool.create_client(endpoint).await?,
    };
    match action.command {
        BiosAttrs => {
            let bios = redfish.bios().await?;
            println!("{}", serde_json::to_string(&bios).unwrap());
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
        SetForgePasswordPolicy => {
            redfish.set_forge_password_policy().await?;
        }
        GetPowerState => {
            println!("{}", redfish.get_power_state().await?);
        }
        GetBootOption(selector) => {
            if let Some(boot_id) = selector.id {
                println!("{:?}", redfish.get_boot_option(&boot_id).await?)
            } else {
                let all = redfish.get_boot_options().await?;
                for b in all.members {
                    let id = b.odata_id.split('/').last().unwrap();
                    println!("{:?}", redfish.get_boot_option(id).await?)
                }
            }
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
                    format!("{} {}", status.health.unwrap_or_default(), status.state),
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
        GetSecureBoot => {
            println!("{:#?}", redfish.get_secure_boot().await?);
        }
        GetBmcAccounts => {
            for u in redfish.get_accounts().await? {
                println!("{u:?}");
            }
        }
        CreateBmcUser(bmc_user) => {
            let role: RoleId = match bmc_user
                .role_id
                .unwrap_or("Administrator".to_string())
                .to_lowercase()
                .as_str()
            {
                "administrator" => RoleId::Administrator,
                "operator" => RoleId::Operator,
                "readonly" => RoleId::ReadOnly,
                "noaccess" => RoleId::NoAccess,
                _ => RoleId::Administrator,
            };
            redfish
                .create_user(&bmc_user.user, &bmc_user.new_password, role)
                .await?;
        }
        ChangeBmcUsername(bmc_username) => {
            redfish
                .change_username(&bmc_username.old_user, &bmc_username.new_user)
                .await?;
            println!(
                "User {} renamed to {}",
                bmc_username.old_user, bmc_username.new_user
            );
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
        GetBmcEthernetInterfaces => {
            handle_ethernet_interface_show(redfish, false).await?;
        }
        GetSystemEthernetInterfaces => {
            handle_ethernet_interface_show(redfish, true).await?;
        }
        GenerateHostUefiPassword => {
            let password = Credentials::generate_password_no_special_char();
            println!("Generated Bios Admin Password: {}", password);
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
    if args.all || args.bmc || args.dpu_os || args.uefi || args.fw.is_empty() {
        let f = FwFilter {
            only_bmc: args.bmc,
            only_dpu_os: args.dpu_os,
            only_uefi: args.uefi,
        };
        match show_all_fws(redfish, f).await {
            Ok(_) => {
                // TODO(chet): Remove this ~March 2024.
                // Use tracing::warn for this so its both a little more
                // noticeable, and a little more annoying/naggy. If people
                // complain, it means its working.
                if args.all {
                    warn!("redundant `--all` with basic `show` is deprecated. just do `fw show`")
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("Error displaying firmware information: {}", e);
                Err(e)
            }
        }
    } else {
        match redfish.get_firmware(&args.fw).await {
            Ok(firmware) => {
                convert_fws_to_nice_table(vec![firmware]).printstd();
                Ok(())
            }
            Err(err) => {
                eprintln!("Error fetching firmware '{}'", args.fw);
                Err(err)
            }
        }
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
    match show_all_ports(redfish).await {
        Ok((mut ports_info, netdev_funcs_info)) => {
            if !args.port.is_empty() {
                ports_info.retain(|f| *f.id.as_ref().unwrap() == args.port);
            }
            convert_ports_to_nice_table(ports_info, netdev_funcs_info).printstd();
            // TODO(chet): Remove this ~March 2024.
            // Use tracing::warn for this so its both a little more
            // noticeable, and a little more annoying/naggy. If people
            // complain, it means its working.
            if args.all {
                warn!("redundant `--all` with basic `show` is deprecated. just do `port show`")
            }
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

pub async fn handle_ethernet_interface_show(
    redfish: Box<dyn Redfish>,
    fetch_system_interfaces: bool,
) -> Result<(), RedfishError> {
    let eth_ifs: Vec<String> = match fetch_system_interfaces {
        false => redfish.get_manager_ethernet_interfaces().await?,
        true => redfish.get_system_ethernet_interfaces().await?,
    };
    let mut eth_ifs_info: Vec<EthernetInterface> = Vec::new();

    for iface_id in eth_ifs.iter() {
        let result = match fetch_system_interfaces {
            false => redfish.get_manager_ethernet_interface(iface_id).await,
            true => redfish.get_system_ethernet_interface(iface_id).await,
        };

        match result {
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
        "IP Addresses",
        "Static IP Addresses",
        "MTU Size",
        "Speed (Mbps)",
    ]);

    for eth_if in &eth_ifs {
        let mut ips = Vec::new();
        for ip in &eth_if.ipv4_addresses {
            if let Some(ip) = ip.address.as_ref() {
                ips.push(ip.clone());
            }
        }
        for ip in &eth_if.ipv6_addresses {
            if let Some(ip) = ip.address.as_ref() {
                ips.push(ip.clone());
            }
        }

        let mut static_ips = Vec::new();
        for ip in &eth_if.ipv4_static_addresses {
            if let Some(ip) = ip.address.as_ref() {
                static_ips.push(ip.clone());
            }
        }
        for ip in &eth_if.ipv6_static_addresses {
            if let Some(ip) = ip.address.as_ref() {
                static_ips.push(ip.clone());
            }
        }

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
            ips.join(","),
            static_ips.join(","),
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
