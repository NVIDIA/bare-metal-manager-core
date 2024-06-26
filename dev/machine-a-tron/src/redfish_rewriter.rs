use crate::bmc_mock_wrapper::MockBmcInfo;
use axum::body::{Body, Bytes};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use lazy_static::lazy_static;
use libredfish::model::{BootOption, ComputerSystem};
use libredfish::EthernetInterface;
use regex::{Captures, Regex};

lazy_static! {
    static ref MANAGERS_ETHERNET_INTERFACES_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Managers/(?<manager_name>[^/]+)/EthernetInterfaces/(?<nic>[^/]+)(/(index.json)?)?$"
    )
    .unwrap();
    static ref SYSTEMS_ETHERNET_INTERFACES_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/(?<manager_name>[^/]+)/EthernetInterfaces/(?<nic>[^/]+)(/(index.json)?)?$"
    )
    .unwrap();
    static ref SYSTEM_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/(?<system_name>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref DPU_BOOT_OPTIONS_REGEX: Regex = Regex::new(
        r"^/redfish/v1/Systems/Bluefield/BootOptions/(?<boot_option_id>[^/]+)(/(index.json)?)?$"
    ).unwrap();
    static ref UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX: Regex = Regex::new(
        r"(?<prefix>.*MAC\()(?<mac>[[:alnum:]]+)(?<suffix>,.*)$"
    ).unwrap();
}

pub fn mock_response_if_needed(
    mock_bmc_info: &MockBmcInfo,
    request: &Request<Body>,
) -> Option<Response<Body>> {
    return match (mock_bmc_info, request.method(), request.uri().path()) {
        // Reboot request
        (_, &Method::POST, "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset") => Some(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(""))
                .unwrap(),
        ),
        // Dell password change, needs a job ID to be returned in the Location: header
        (
            MockBmcInfo::Host(_),
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
            MockBmcInfo::Host(_),
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

pub fn rewritten_response_if_needed(
    mock_bmc_info: &MockBmcInfo,
    path: &str,
    response: &[u8],
) -> eyre::Result<Option<Bytes>> {
    if let Some(captures) = MANAGERS_ETHERNET_INTERFACES_REGEX.captures(path) {
        let mut iface = serde_json::from_slice::<EthernetInterface>(response)?;
        match mock_bmc_info {
            MockBmcInfo::Dpu(dpu) => {
                if captures["manager_name"].ne("Bluefield_BMC") {
                    tracing::error!("request for Managers data for DPU, when Manager is not Bluefield_BMC... upstream bmc-mock should have 404'd? {}", path);
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
            MockBmcInfo::Host(host) => {
                iface.mac_address = Some(host.bmc_mac_address.to_string());
            }
        }
        return Ok(Some(Bytes::from(serde_json::to_string(&iface)?)));
    }

    if let Some(captures) = SYSTEMS_ETHERNET_INTERFACES_REGEX.captures(path) {
        let mut iface = serde_json::from_slice::<EthernetInterface>(response)?;
        match mock_bmc_info {
            MockBmcInfo::Dpu(dpu) => {
                if captures["manager_name"].ne("Bluefield") {
                    tracing::error!("request for Systems data for DPU, when System is not Bluefield... upstream bmc-mock should have 404'd? {}", path);
                    return Ok(None);
                }
                iface.mac_address = Some(dpu.host_mac_address.to_string());
            }
            MockBmcInfo::Host(host) => {
                iface.mac_address = host.system_mac_addresss().map(|m| m.to_string());
            }
        }
        return Ok(Some(Bytes::from(serde_json::to_string(&iface)?)));
    }

    if SYSTEM_REGEX.is_match(path) {
        let mut system = serde_json::from_slice::<ComputerSystem>(response)?;
        system.serial_number = Some(mock_bmc_info.serial().to_string());
        return Ok(Some(Bytes::from(serde_json::to_string(&system)?)));
    }

    if DPU_BOOT_OPTIONS_REGEX.is_match(path) {
        // We only rewrite this line if it's a DPU we're mocking
        let MockBmcInfo::Dpu(dpu) = mock_bmc_info else {
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
        return Ok(Some(Bytes::from(serde_json::to_string(&boot_option)?)));
    }

    Ok(None)
}
