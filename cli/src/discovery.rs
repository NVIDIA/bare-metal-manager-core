extern crate libudev;

use cli::{CarbideClientError, CarbideClientResult};
use rpc::v0 as rpc;

use libudev::{Context, Device};
use log::{debug, error};
use once_cell::sync::Lazy;
use std::str::Utf8Error;
use tokio::runtime::{Builder, Runtime};
use tonic::Response;

pub struct Discovery {}

pub fn get_tokio_runtime() -> &'static Runtime {
    static TOKIO: Lazy<Runtime> =
        Lazy::new(|| Builder::new_current_thread().enable_all().build().unwrap());

    &TOKIO
}

fn convert_udev_to_mac(udev: String) -> CarbideClientResult<String> {
    // udevs format is enx112233445566 first, then the string of octets without a colon
    // remove the enx characters
    let (_, removed_enx) = udev.split_at(3);
    // chunk into 2 length
    let chunks = removed_enx
        .as_bytes()
        .chunks(2)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, Utf8Error>>()
        .map_err(CarbideClientError::from)?;
    // add colons
    let mut mac = chunks
        .into_iter()
        .map(|chunk| format!("{}:", chunk))
        .collect::<String>();
    // remove trailing colon from the above format
    mac.pop();

    Ok(mac)
}

fn convert_property_to_string<'a>(
    name: &'a str,
    default_value: &'a str,
    device: &'a Device,
) -> CarbideClientResult<&'a str> {
    return match device.property_value(name) {
        None => match default_value.len() {
            0 => Err(CarbideClientError::GenericError(format!(
                "Could not find property {}",
                name
            ))),
            _ => Ok(default_value),
        },
        Some(p) => p.to_str().ok_or(CarbideClientError::GenericError(format!(
            "Could not transform os string to string for property {}",
            name
        ))),
    };
}

pub fn get_machine_details(
    context: &Context,
    uuid: &str,
) -> CarbideClientResult<rpc::MachineDiscovery> {
    // Nics
    let mut enumerator = libudev::Enumerator::new(&context)
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;
    enumerator
        .match_subsystem("net")
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;
    let devices = enumerator
        .scan_devices()
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;

    // let fff = devices.map(|device|DiscoveryNic { mac: "".to_string(), dev: "".to_string() });
    let mut nics: Vec<rpc::MachineDiscoveryNic> = Vec::new();
    for device in devices {
        debug!("{:?}", device.syspath());
        for p in device.properties() {
            debug!("{:?} - {:?}", p.name(), p.value());
        }

        if let Some(_) = device
            .property_value("ID_PCI_SUBCLASS_FROM_DATABASE")
            .filter(|v| v.eq_ignore_ascii_case("Ethernet controller"))
        {
            nics.push(rpc::MachineDiscoveryNic {
                mac_address: convert_udev_to_mac(
                    convert_property_to_string("ID_NET_NAME_MAC", "", &device)?.to_string(),
                )?,
                device: convert_property_to_string("ID_NET_NAME_PATH", "", &device)?.to_string(),
            });
        }
    }

    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info =
        procfs::CpuInfo::new().or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;

    let mut cpus: Vec<rpc::MachineDiscoveryCpu> = Vec::new();
    for cpu_num in 0..cpu_info.num_cores() {
        debug!("{:?}", cpu_info.get_info(cpu_num));
        cpus.push(rpc::MachineDiscoveryCpu {
            vendor: cpu_info
                .vendor_id(cpu_num)
                .ok_or(CarbideClientError::GenericError(
                    "Could not get model name".to_string(),
                ))?
                .to_string(),
            model: cpu_info
                .model_name(cpu_num)
                .ok_or(CarbideClientError::GenericError(
                    "Could not get model name".to_string(),
                ))?
                .to_string(),
            frequency: cpu_info
                .get_info(cpu_num)
                .ok_or(CarbideClientError::GenericError(
                    "Could not get cpu info".to_string(),
                ))?
                .get("cpu MHz")
                .ok_or(CarbideClientError::GenericError(
                    "Could not get cpu MHz field".to_string(),
                ))?
                .to_string(),
            num: cpu_num as i32,
        });
    }

    // disks
    let mut enumerator = libudev::Enumerator::new(&context)
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;
    enumerator
        .match_subsystem("block")
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;
    let devices = enumerator
        .scan_devices()
        .or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;

    let mut disks: Vec<rpc::MachineDiscoveryBlockDevice> = Vec::new();

    for device in devices {
        debug!("{:?}", device.syspath());
        for p in device.properties() {
            debug!("{:?} - {:?}", p.name(), p.value());
        }

        if let Some(_) = device
            .property_value("DEVPATH")
            .map(|v| v.to_str())
            .ok_or(CarbideClientError::GenericError(
                "Could not decode DEVPATH".to_string(),
            ))?
            .filter(|v| !v.contains("virtual"))
        {
            disks.push(rpc::MachineDiscoveryBlockDevice {
                path: convert_property_to_string("DEVPATH", "", &device)?.to_string(),
                model: convert_property_to_string("ID_MODEL", "NO_MODEL", &device)?.to_string(),
                revision: convert_property_to_string("ID_REVISION", "NO_REVISION", &device)?
                    .to_string(),
                serial: convert_property_to_string("ID_SERIAL_SHORT", "NO_SERIAL", &device)?
                    .to_string(),
            });
        }
    }

    let rpc_uuid: rpc::Uuid = uuid::Uuid::parse_str(uuid)
        .map(|m| m.into())
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    Ok(rpc::MachineDiscovery {
        uuid: Some(rpc_uuid),
        nics,
        cpus,
        devices: disks,
    })
}

impl Discovery {
    pub async fn run(listen: String, uuid: &str) -> CarbideClientResult<Response<rpc::Machine>> {
        let context = libudev::Context::new().map_err(CarbideClientError::from)?;
        let info = get_machine_details(&context, uuid)?;
        let mut client = rpc::metal_client::MetalClient::connect(listen).await?;
        let request = tonic::Request::new(info);
        Ok(client.discover_machine(request).await?)
    }
}
