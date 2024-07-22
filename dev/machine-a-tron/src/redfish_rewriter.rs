#![allow(unused_imports)]
use crate::bmc_mock_wrapper::MachineCommand;
use crate::machine_info::MachineInfo;
use axum::body::{Body, Bytes};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use chrono::Utc;
use lazy_static::lazy_static;
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::{BootOption, ComputerSystem, ODataId};
use libredfish::{Chassis, EthernetInterface, NetworkAdapter};
use regex::{Captures, Regex};
use std::collections::HashMap;
use tokio::sync::mpsc;

lazy_static! {
    static ref MANAGERS_ETHERNET_INTERFACES_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Managers/(?<manager_name>[^/]+)/EthernetInterfaces/(?<nic>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref SYSTEMS_ETHERNET_INTERFACES_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/(?<system_name>[^/]+)/EthernetInterfaces/(?<nic>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref CHASSIS_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Chassis/(?<chassis_name>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref CHASSIS_NETWORK_ADAPTERS_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Chassis/(?<chassis_name>[^/]+)/NetworkAdapters(/(index.json)?)?$"
    ).unwrap();
    static ref CHASSIS_NETWORK_ADAPTERS_NIC_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Chassis/(?<chassis_name>[^/]+)/NetworkAdapters/(?<nic>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref SYSTEM_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/(?<system_name>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref DPU_BOOT_OPTIONS_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/Bluefield/BootOptions/(?<boot_option_id>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX: Regex = Regex::new(
        r"(?<prefix>.*MAC\()(?<mac>[[:alnum:]]+)(?<suffix>,.*)$"
    ).unwrap();
    static ref DPU_SYS_IMAGE_REGEX: Regex = Regex::new(
        r"^/redfish/v1/UpdateService/FirmwareInventory/DPU_SYS_IMAGE(/(index.json)?)?$"
    ).unwrap();
    static ref SYSTEM_RESET_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/(?<system_name>[^/]+)/Actions/ComputerSystem.Reset(/(index.json)?)?$"
    ).unwrap();
}

pub fn mock_response_if_needed(
    machine_info: &MachineInfo,
    request: &Request<Body>,
) -> Option<Response<Body>> {
    if let Some(captures) = CHASSIS_NETWORK_ADAPTERS_NIC_REGEX.captures(request.uri().path()) {
        return generate_network_adapters_response(captures, machine_info);
    }

    return match (machine_info, request.method(), request.uri().path()) {
        // Dell password change, needs a job ID to be returned in the Location: header
        (
            MachineInfo::Host(_),
            &Method::POST,
            "/redfish/v1/Systems/System.Embedded.1/Bios/Settings",
        ) => Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    "Location",
                    "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/JID_00000000001",
                )
                .body(Body::from(""))
                .unwrap(),
        ),
        (
            MachineInfo::Host(_),
            &Method::POST,
            "/redfish/v1/Systems/1/Bios/Actions/Bios.ChangePassword",
        ) => Some(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(""))
                .unwrap(),
        ),
        _ => None,
    };
}

/// Take a given HTTP request path given to BMC-mock, and its response, and return a modified
/// response, if applicable.
pub fn rewritten_response_if_needed(
    machine_info: &MachineInfo,
    path: &str,
    response: &[u8],
    command_channel: &mpsc::UnboundedSender<MachineCommand>,
) -> eyre::Result<Option<Bytes>> {
    return if CHASSIS_REGEX.is_match(path) {
        rewrite_chassis_response(machine_info, response)
    } else if SYSTEM_REGEX.is_match(path) {
        rewrite_system_response(machine_info, response)
    } else if DPU_BOOT_OPTIONS_REGEX.is_match(path) {
        rewrite_dpu_boot_options_response(machine_info, response)
    } else if DPU_SYS_IMAGE_REGEX.is_match(path) {
        rewrite_dpu_sys_image_response(machine_info, response)
    } else if SYSTEM_RESET_REGEX.is_match(path) {
        perform_reset(command_channel);
        Ok(None)
    } else if let Some(captures) = MANAGERS_ETHERNET_INTERFACES_REGEX.captures(path) {
        rewrite_managers_ethernet_interfaces_response(captures, machine_info, response)
    } else if let Some(captures) = SYSTEMS_ETHERNET_INTERFACES_REGEX.captures(path) {
        rewrite_systems_ethernet_interfaces_response(captures, machine_info, response)
    } else if let Some(captures) = CHASSIS_NETWORK_ADAPTERS_REGEX.captures(path) {
        rewrite_chassis_network_adapters_response(captures, machine_info, response)
    } else {
        Ok(None)
    };
}

// MARK: - Response generating functions

fn generate_network_adapters_response(
    captures: Captures,
    machine_info: &MachineInfo,
) -> Option<Response<Body>> {
    let MachineInfo::Host(host) = machine_info else {
        return None;
    };
    let nic_id = captures["nic"].to_string();
    if !nic_id.starts_with("NIC.Slot.") {
        tracing::info!("Ignoring request for non-DPU NIC {nic_id}");
        return None;
    }
    let dpu_index = nic_id.chars().last().unwrap().to_digit(10).unwrap() as usize;
    let Some(dpu) = host.dpus.get(dpu_index - 1) else {
        tracing::error!("Request for NIC ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request", nic_id, host.dpus.len());
        return None;
    };

    // Build a NetworkAdapter from our mock DPU info (mainly just the serial number)
    let adapter = NetworkAdapter {
        id: nic_id,
        manufacturer: Some("Mellanox Technologies".to_string()),
        model: Some("BlueField-2 SmartNIC Main Card".to_string()),
        part_number: Some("MBF2H5".to_string()),
        serial_number: Some(dpu.serial.clone()),
        odata: libredfish::OData {
            odata_id: "odata_id".to_owned(),
            odata_type: "odata_type".to_owned(),
            odata_etag: None,
            odata_context: None,
        },
        ports: None,
        network_device_functions: None,
        name: None,
        status: None,
        controllers: None,
    };
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(serde_json::to_string(&adapter).ok()?))
            .unwrap(),
    )
}

// MARK: - Response rewriting functions

fn rewrite_managers_ethernet_interfaces_response(
    captures: Captures,
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    let mut iface = serde_json::from_slice::<EthernetInterface>(response)?;
    match machine_info {
        MachineInfo::Dpu(dpu) => {
            if captures["manager_name"].ne("Bluefield_BMC") {
                tracing::error!("request for Managers data for DPU, when Manager is not Bluefield_BMC... upstream bmc-mock should have 404'd?");
                return Ok(None);
            }
            if iface
                .id
                .as_ref()
                .map(|name| name.eq("eth0"))
                .unwrap_or(false)
            {
                iface.mac_address = Some(dpu.bmc_mac_address.to_string());
            } else {
                return Ok(None);
            }
        }
        MachineInfo::Host(host) => {
            iface.mac_address = Some(host.bmc_mac_address.to_string());
        }
    }
    Ok(Some(Bytes::from(serde_json::to_string(&iface)?)))
}

fn rewrite_systems_ethernet_interfaces_response(
    captures: Captures,
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    let mut iface = serde_json::from_slice::<EthernetInterface>(response)?;
    match machine_info {
        MachineInfo::Dpu(dpu) => {
            if captures["system_name"].ne("Bluefield") {
                tracing::error!("request for Systems data for DPU, when System is not Bluefield... upstream bmc-mock should have 404'd?");
                return Ok(None);
            }
            iface.mac_address = Some(dpu.host_mac_address.to_string());
        }
        MachineInfo::Host(host) => {
            iface.mac_address = host.system_mac_address().map(|m| m.to_string());
        }
    }
    Ok(Some(Bytes::from(serde_json::to_string(&iface)?)))
}

fn rewrite_chassis_response(
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    let mut chassis: Chassis = serde_json::from_slice(response)?;
    chassis.serial_number = machine_info.chassis_serial();
    Ok(Some(Bytes::from(serde_json::to_string(&chassis)?)))
}

fn rewrite_chassis_network_adapters_response(
    captures: Captures,
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    let MachineInfo::Host(host) = machine_info else {
        return Ok(None);
    };
    let mut body: HashMap<String, serde_json::Value> = serde_json::from_slice(response)?;

    // Discard the "members" array from the upstream request, build our own.
    body.remove("Members");

    // Add stock adapters, embedded and integrated
    let mut members = Vec::<ODataId>::from(&[
        ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Embedded.1",
                &captures["chassis_name"],
            ),
        },
        ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Integrated.1",
                &captures["chassis_name"],
            ),
        },
    ]);

    // Add a network adapter for every DPU
    for (index, _dpu) in host.dpus.iter().enumerate() {
        members.push(ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Slot.{}",
                &captures["chassis_name"],
                index + 1
            ),
        })
    }
    let members_len = members.len();
    body.insert(
        "Members".to_string(),
        serde_json::to_value(members).unwrap(),
    );

    body.remove("Members@odata.count");
    body.insert(
        "Members@odata.count".to_string(),
        serde_json::to_value(members_len).unwrap(),
    );
    Ok(Some(Bytes::from(serde_json::to_string(&body)?)))
}

fn rewrite_system_response(
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    let mut system = serde_json::from_slice::<ComputerSystem>(response)?;
    system.serial_number = machine_info.product_serial();
    Ok(Some(Bytes::from(serde_json::to_string(&system)?)))
}

fn rewrite_dpu_boot_options_response(
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = machine_info else {
        return Ok(None);
    };
    let mut boot_option = serde_json::from_slice::<BootOption>(response)?;
    let Some(uefi_device_path) = boot_option.uefi_device_path else {
        return Ok(None);
    };
    let mocked_mac_no_colons = dpu
        .oob_mac_address
        .to_string()
        .replace(':', "")
        .to_ascii_uppercase();
    let updated_uefi_device_path =
        UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX.replace(&uefi_device_path, |captures: &Captures| {
            [
                &captures["prefix"],
                &mocked_mac_no_colons,
                &captures["suffix"],
            ]
            .join("")
        });
    boot_option.uefi_device_path = Some(updated_uefi_device_path.to_string());
    Ok(Some(Bytes::from(serde_json::to_string(&boot_option)?)))
}

fn rewrite_dpu_sys_image_response(
    machine_info: &MachineInfo,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = machine_info else {
        return Ok(None);
    };

    let mut inventory = serde_json::from_slice::<SoftwareInventory>(response)?;
    let mut base_mac = dpu.host_mac_address.to_string();
    base_mac = base_mac.replace(':', "");
    if base_mac.len() != 12 {
        tracing::warn!(
            "Invalid FirmwareInventory length after removing ':': {}",
            base_mac.len()
        );
    }

    // Version string is the mac address with extra padding in the middle to reach 64 bits, and
    // colons after every 16 bits instead of 8. Carbide will reverse this, removing the middle
    // padding and rearranging the colons to form a mac address.

    // base_mac example: 123456abcdef
    base_mac.insert(6, '0');
    base_mac.insert(6, '0');
    base_mac.insert(6, '0');
    base_mac.insert(6, '0'); // now 1234560000abcdef
    base_mac.insert(12, ':'); // now 1234560000ab:cdef
    base_mac.insert(8, ':'); // now 12345600:00ab:cdef
    base_mac.insert(4, ':'); // now 1234:5600:00ab:cdef

    inventory.version = Some(base_mac);

    Ok(Some(Bytes::from(serde_json::to_string(&inventory)?)))
}

fn perform_reset(command_channel: &mpsc::UnboundedSender<MachineCommand>) {
    command_channel
        .send(MachineCommand::Reboot(Utc::now()))
        .unwrap()
}
