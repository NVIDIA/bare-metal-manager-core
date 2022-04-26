extern crate core;
extern crate libudev;

use libudev::{Context, Device, Property};
use log::{debug, warn};
use log::{error, info};
use once_cell::sync::Lazy;
use rpc::v0 as rpc;
use serde::{Deserialize, Serialize};
use std::env;
use tokio::runtime::{Builder, Runtime};
use tonic::{IntoRequest, Response, Status};

#[derive(thiserror::Error, Debug)]
pub enum CarbideClientError {
    #[error("Generic error: {0}")]
    GenericError(String),
}

pub type CarbideClientResult<T> = Result<T, CarbideClientError>;

// #[derive(Serialize, Deserialize, Debug)]
// struct DiscoveryNic {
//     mac: String,
//     dev: String,
// }
//
// #[derive(Serialize, Deserialize, Debug)]
// struct DiscoveryCpu {
//     model: String,
//     vendor: String,
//     frequency: String,
//     num: usize,
// }
//
// #[derive(Serialize, Deserialize, Debug)]
// struct DiscoveryBlockDevice {
//     path: String,
//     model: String,
//     revision: String,
//     serial: String,
// }
//
// #[derive(Serialize, Deserialize, Debug)]
// struct DiscoveryInfo {
//     nics: Vec<DiscoveryNic>,
//     cpu: DiscoveryCpu,
//     block_devices: Vec<DiscoveryBlockDevice>,
// }

pub fn get_tokio_runtime() -> &'static Runtime {
    static TOKIO: Lazy<Runtime> =
        Lazy::new(|| Builder::new_current_thread().enable_all().build().unwrap());

    &TOKIO
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    match args.len() {
        2 => {
            let strarg = args.remove(1);
            let arg = strarg.as_str();
            match arg {
                "discovery" => match discovery() {
                    Ok(_) => {} // Do nothing, discovery worked.
                    Err(e) => {
                        log::error!("{:?}", e);
                        panic!("Discovery failed, please see error logs");
                    }
                },
                v => {
                    panic!("Did not understand verb: {:?}", v)
                }
            }
        }
        _ => {
            panic!("Unknown number of arguments {:?}", args)
        }
    }
}

fn convert_property_to_string<'a>(
    name: &'a str,
    device: &'a Device,
) -> CarbideClientResult<&'a str> {
    device
        .property_value(name)
        .ok_or(CarbideClientError::GenericError(format!(
            "Could not find property {}",
            name
        )))
        .map(|v| v.to_str())?
        .ok_or(CarbideClientError::GenericError(format!(
            "Could not transform os string to string for property {}",
            name
        )))
}

fn get_machine_details(context: &Context) -> CarbideClientResult<rpc::MachineDiscovery> {
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
        if let Some(_) = device
            .property_value("ID_PCI_SUBCLASS_FROM_DATABASE")
            .filter(|v| v.eq_ignore_ascii_case("Ethernet controller"))
        {
            nics.push(rpc::MachineDiscoveryNic {
                mac_address: convert_property_to_string("ID_NET_NAME_MAC", &device)?.to_string(),
                device: convert_property_to_string("ID_NET_NAME_PATH", &device)?.to_string(),
            });
        }
    }

    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info =
        procfs::CpuInfo::new().or_else(|e| Err(CarbideClientError::GenericError(e.to_string())))?;

    let mut cpus: Vec<rpc::MachineDiscoveryCpu> = Vec::new();
    for cpu_num in 0..cpu_info.num_cores() {
        cpus.push(rpc::MachineDiscoveryCpu {
            vendor: cpu_info.vendor_id(cpu_num).ok_or(CarbideClientError::GenericError(
                "Could not get model name".to_string(),
            ))?.to_string(),
            model: cpu_info.model_name(cpu_num).ok_or(CarbideClientError::GenericError(
                            "Could not get model name".to_string(),
                        ))?.to_string(),
            frequency: cpu_info.get_info(cpu_num).ok_or(CarbideClientError::GenericError(
                "Could not get cpu info".to_string(),
            ))?.get("cpu MHz").ok_or(CarbideClientError::GenericError(
                "Could not get cpu MHz field".to_string(),
            ))?.to_string(),
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
        //println!("{:?}", device.properties());
        if let Some(_) = device
            .property_value("DEVPATH")
            .map(|v| v.to_str())
            .ok_or(CarbideClientError::GenericError(
                "Could not decode DEVPATH".to_string(),
            ))?
            .filter(|v| !v.contains("block"))
        {
            disks.push(rpc::MachineDiscoveryBlockDevice {
                path: convert_property_to_string("DEVPATH", &device)?.to_string(),
                model: convert_property_to_string("ID_MODEL", &device)?.to_string(),
                revision: convert_property_to_string("ID_REVISION", &device)?.to_string(),
                serial: convert_property_to_string("ID_SERIAL_SHORT", &device)?.to_string(),
            });
        }
    }

    Ok(rpc::MachineDiscovery {
        nics,
        cpus,
        devices: disks,
    })
}

fn discovery() -> Result<Response<rpc::Machine>, CarbideClientError> {
    let context =
        libudev::Context::new().map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    let di_info = get_machine_details(&context)
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    // Spawn a tokio runtime and schedule the API connection and machine retrieval to an async
    // thread.  This is required beause tonic is async but this code generally is not.
    //
    // TODO(ajf): how to reason about FFI code with async.
    //
    let runtime: &tokio::runtime::Runtime = get_tokio_runtime();

    runtime.block_on(async move {
        match rpc::metal_client::MetalClient::connect("https://[::1]:1079".to_string()).await {
            Ok(mut client) => {
                let request = tonic::Request::new(di_info);
                client.discover_machine(request).await.map_err(|error| {
                    error!("Unable to discover machine via Carbide {:?}", error);
                    CarbideClientError::GenericError(error.to_string())
                })
            }
            Err(err) => {
                error!("unable to connect to Carbide API: {:?}", err);
                Err(CarbideClientError::GenericError(err.to_string()))
            }
        }
    })
}
