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
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    str::{FromStr, Utf8Error},
};

use ::rpc::machine_discovery as rpc_discovery;
use libudev::Device;
use log::error;
use uname::uname;

mod dpu;
mod tpm;

const PCI_SUBCLASS: &str = "ID_PCI_SUBCLASS_FROM_DATABASE";
const PCI_VENDOR_ID: &str = "ID_VENDOR_ID";
const PCI_MODEL_ID: &str = "ID_MODEL_ID";
const PCI_DEV_PATH: &str = "DEVPATH";
const PCI_MODEL: &str = "ID_MODEL_FROM_DATABASE";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CpuArchitecture {
    Aarch64,
    X86_64,
}

impl FromStr for CpuArchitecture {
    type Err = HardwareEnumerationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arch = match s {
            "aarch64" => Ok(CpuArchitecture::Aarch64),
            "x86_64" => Ok(CpuArchitecture::X86_64),
            _ => Err(HardwareEnumerationError::UnsupportedCpuArchitecture(
                s.to_string(),
            )),
        }?;
        Ok(arch)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HardwareEnumerationError {
    #[error("Hardware enumeration error: {0}")]
    GenericError(String),
    #[error("Udev failed with error: {0}")]
    UdevError(#[from] libudev::Error),
    #[error("Udev string {0} is not a valid MAC address")]
    InvalidMacAddress(String),
    #[error("CPU architecture {0} is not supported")]
    UnsupportedCpuArchitecture(String),
}

fn convert_udev_to_mac(udev: String) -> Result<String, HardwareEnumerationError> {
    // udevs format is enx112233445566 first, then the string of octets without a colon
    // remove the enx characters
    let (_, removed_enx) = udev.split_at(3);
    // chunk into 2 length
    let chunks = removed_enx
        .as_bytes()
        .chunks(2)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, Utf8Error>>()
        .map_err(|_| HardwareEnumerationError::InvalidMacAddress(udev.clone()))?;
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
) -> Result<&'a str, HardwareEnumerationError> {
    match device.property_value(name) {
        None => match default_value.is_empty() {
            true => Err(HardwareEnumerationError::GenericError(format!(
                "Could not find property {}",
                name
            ))),
            false => Ok(default_value),
        },
        Some(p) => p.to_str().map(|s| s.trim()).ok_or_else(|| {
            HardwareEnumerationError::GenericError(format!(
                "Could not transform os string to string for property {}",
                name
            ))
        }),
    }
}

fn convert_sysattr_to_string<'a>(
    name: &'a str,
    device: &'a Device,
) -> Result<&'a str, HardwareEnumerationError> {
    match device.attribute_value(name) {
        None => Ok(""),
        Some(p) => p.to_str().map(|s| s.trim()).ok_or_else(|| {
            HardwareEnumerationError::GenericError(format!(
                "Could not transform os string to string for attribute {}",
                name
            ))
        }),
    }
}

// NUMA_NODE is not exposed in libudev but the full path to a device is.
// We have to convert from String -> i32 which is full of cases where conversion
// can fail. Rather than cause the client to error out during discovery, we use the
// largest i32 as an indicator that the host is likely in a bad state as there is no
// valid reason why the `numa_node` file on the /proc filesystem would contain garbage
fn get_numa_node_from_syspath(syspath: Option<&Path>) -> Result<i32, HardwareEnumerationError> {
    const NUMA_NODE_ESCAPE_HATCH: i32 = 2147483647;

    if let Some(v) = syspath {
        let numa_node_full_path = v.to_path_buf().join("device/numa_node");

        let file_path = match fs::File::open(numa_node_full_path) {
            Ok(file) => file,
            Err(_) => return Ok(NUMA_NODE_ESCAPE_HATCH), // TODO(baz): better error handling for DPUs
        };

        let file_reader = BufReader::new(file_path);

        let numa_node_value = file_reader.lines().next();
        let result: i32 = match numa_node_value {
            None => NUMA_NODE_ESCAPE_HATCH,
            Some(v) => {
                let res = match v {
                    Ok(l) => Ok(l.parse::<i32>().unwrap_or(NUMA_NODE_ESCAPE_HATCH)),
                    Err(e) => return Err(HardwareEnumerationError::GenericError(e.to_string())),
                };
                return res;
            }
        };
        Ok(result)
    } else {
        Ok(NUMA_NODE_ESCAPE_HATCH)
    }
}

pub fn enumerate_hardware() -> Result<rpc_discovery::DiscoveryInfo, HardwareEnumerationError> {
    let context = libudev::Context::new()?;

    // uname to detect type
    let info = uname().map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;
    let arch = info.machine.parse()?;

    log::trace!("{:?}", info);

    let device_debug_log = |device: &Device| {
        log::debug!("SysPath - {:?}", device.syspath());
        for p in device.properties() {
            log::debug!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::debug! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    };

    // IBs
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("infiniband")?;
    let devices = enumerator.scan_devices()?;

    // PCI_DEV_PATH - "/devices/pci0000:b0/0000:b0:02.0/0000:b1:00.1/infiniband/mlx5_5"
    // PCI_MODEL_ID - "0x1017"
    // PCI_MODEL - "MT27800 Family [ConnectX-5]"
    // PCI_SUBCLASS - "Infiniband controller"
    // PCI_VENDOR_ID - "0x15b3"
    // "NAME" - "mlx5_5"
    // "node_guid" - Some("1070:fd03:0017:660d")
    // "sys_image_guid" - Some("1070:fd03:0017:660c")
    let mut ibs: Vec<rpc_discovery::InfinibandInterface> = Vec::new();

    for device in devices {
        device_debug_log(&device);

        if device
            .property_value(PCI_SUBCLASS)
            .filter(|v| v.eq_ignore_ascii_case("Infiniband controller"))
            .is_none()
        {
            continue;
        }

        ibs.push(rpc_discovery::InfinibandInterface {
            guid: convert_sysattr_to_string("node_guid", &device)?
                .to_string()
                .replace(':', ""),
            pci_properties: Some(rpc_discovery::PciDeviceProperties {
                vendor: convert_property_to_string(PCI_VENDOR_ID, "", &device)?.to_string(),
                device: convert_property_to_string(PCI_MODEL_ID, "", &device)?.to_string(),
                path: convert_property_to_string(PCI_DEV_PATH, "", &device)?.to_string(),
                numa_node: get_numa_node_from_syspath(device.syspath())?,
                description: Some(convert_property_to_string(PCI_MODEL, "", &device)?.to_string()),
            }),
        });
    }

    // Nics
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("net")?;
    let devices = enumerator.scan_devices()?;

    // mellanox ID_MODEL_ID = "0xa2d6"
    // mellanox ID_VENDOR_ID = "0x15b3"
    // mellanox ID_MODEL_FROM_DATABASE = "MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"
    // pci_device_path = DEVPATH = "/devices/pci0000:00/0000:00:1c.4/0000:08:00.0/net/enp8s0f0np0"
    // let fff = devices.map(|device|DiscoveryNic { mac: "".to_string(), dev: "".to_string() });
    let mut nics: Vec<rpc_discovery::NetworkInterface> = Vec::new();

    for device in devices {
        log::debug!("SysPath - {:?}", device.syspath());
        for p in device.properties() {
            log::trace!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::trace! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }

        if device
            .property_value(PCI_SUBCLASS)
            .filter(|v| v.eq_ignore_ascii_case("Ethernet controller"))
            .is_some()
        {
            nics.push(rpc_discovery::NetworkInterface {
                mac_address: convert_udev_to_mac(
                    convert_property_to_string("ID_NET_NAME_MAC", &info.machine, &device)?
                        .to_string(),
                )?,
                pci_properties: Some(rpc_discovery::PciDeviceProperties {
                    vendor: convert_property_to_string(PCI_VENDOR_ID, "", &device)?.to_string(),
                    device: convert_property_to_string(PCI_MODEL_ID, "", &device)?.to_string(),
                    path: convert_property_to_string(PCI_DEV_PATH, "", &device)?.to_string(),
                    numa_node: get_numa_node_from_syspath(device.syspath())?,
                    description: Some(
                        convert_property_to_string(PCI_MODEL, "", &device)?.to_string(),
                    ),
                }),
            });
        }
    }
    // on x86 physical_package_id == physical socket number
    // package_cpu_list = list of CPU's sharing the same physical_package_id
    // core_cpus_list = list of CPU's within the same core
    // key name in attribute of 'nodeX' indicates the numa node the CPU is part of
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("cpu")?;
    let devices = enumerator.scan_devices()?;

    for device in devices {
        log::debug!("Syspath - {:?}", device.syspath());
        for p in device.properties() {
            log::trace!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::trace! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    }
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("node")?;
    let devices = enumerator.scan_devices()?;

    for device in devices {
        log::debug!("Syspath - {:?}", device.syspath());
        for p in device.properties() {
            log::trace!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::trace! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    }
    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info = procfs::CpuInfo::new()
        .map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;

    let mut cpus: Vec<rpc_discovery::Cpu> = Vec::new();
    for cpu_num in 0..cpu_info.num_cores() {
        log::debug!("{:?}", cpu_info.get_info(cpu_num));
        match arch {
            CpuArchitecture::Aarch64 => {
                cpus.push(rpc_discovery::Cpu {
                    vendor: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("CPU implementer"))
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get arm vendor name".to_string(),
                            )
                        })?
                        .to_string(),
                    model: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("CPU variant"))
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get arm model name".to_string(),
                            )
                        })?
                        .to_string(),
                    frequency: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("BogoMIPS"))
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get arm frequency".to_string(),
                            )
                        })?
                        .to_string(),
                    number: cpu_num as u32,
                    socket: 0,
                    core: 0,
                    node: 2,
                });
            }
            CpuArchitecture::X86_64 => {
                cpus.push(rpc_discovery::Cpu {
                    vendor: cpu_info
                        .vendor_id(cpu_num)
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get vendor name".to_string(),
                            )
                        })?
                        .to_string(),
                    model: cpu_info
                        .model_name(cpu_num)
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get model name".to_string(),
                            )
                        })?
                        .to_string(),
                    frequency: cpu_info
                        .get_info(cpu_num)
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get cpu info".to_string(),
                            )
                        })?
                        .get("cpu MHz")
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get cpu MHz field".to_string(),
                            )
                        })?
                        .to_string(),
                    number: cpu_num as u32,
                    socket: cpu_info.physical_id(cpu_num).ok_or_else(|| {
                        HardwareEnumerationError::GenericError("Could not get cpu info".to_string())
                    })?,
                    core: cpu_info
                        .get_info(cpu_num)
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get cpu info".to_string(),
                            )
                        })?
                        .get("core id")
                        .map(|c| c.parse::<u32>().unwrap_or(0))
                        .ok_or_else(|| {
                            HardwareEnumerationError::GenericError(
                                "Could not get cpu core id field".to_string(),
                            )
                        })?,
                    node: 0,
                });
            }
        }
    }

    // disks
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("block")?;
    let devices = enumerator.scan_devices()?;

    let mut disks: Vec<rpc_discovery::BlockDevice> = Vec::new();

    for device in devices {
        log::debug!("{:?}", device.syspath());
        for p in device.properties() {
            log::trace!("{:?} - {:?}", p.name(), p.value());
        }

        if device
            .property_value(PCI_DEV_PATH)
            .map(|v| v.to_str())
            .ok_or_else(|| {
                HardwareEnumerationError::GenericError("Could not decode DEVPATH".to_string())
            })?
            .filter(|v| !v.contains("virtual"))
            .is_some()
        {
            disks.push(rpc_discovery::BlockDevice {
                model: convert_property_to_string("ID_MODEL", "NO_MODEL", &device)?.to_string(),
                revision: convert_property_to_string("ID_REVISION", "NO_REVISION", &device)?
                    .to_string(),
                serial: convert_property_to_string("ID_SERIAL_SHORT", "NO_SERIAL", &device)?
                    .to_string(),
            });
        }
    }

    // Nvme
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("nvme")?;
    let devices = enumerator.scan_devices()?;

    let mut nvmes: Vec<rpc_discovery::NvmeDevice> = Vec::new();

    for device in devices {
        log::debug!("{:?}", device.syspath());
        for p in device.properties() {
            log::trace!("{:?} - {:?}", p.name(), p.value());
        }

        if device
            .property_value(PCI_DEV_PATH)
            .map(|v| v.to_str())
            .ok_or_else(|| {
                HardwareEnumerationError::GenericError("Could not decode DEVPATH".to_string())
            })?
            .filter(|v| !v.contains("virtual"))
            .is_some()
        {
            nvmes.push(rpc_discovery::NvmeDevice {
                model: convert_sysattr_to_string("model", &device)?.to_string(),
                firmware_rev: convert_sysattr_to_string("firmware_rev", &device)?.to_string(),
            });
        }
    }

    // Dmi
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("dmi")?;
    let mut devices = enumerator.scan_devices()?;

    let mut dmi = rpc_discovery::DmiData::default();
    // We only enumerate the first set of dmi data
    // There is only expected to be a single set, and we don't want to
    // accidentally overwrite it with other data
    if let Some(device) = devices.next() {
        log::debug!("{:?}", device.syspath());
        for p in device.properties() {
            log::trace!("{:?} - {:?}", p.name(), p.value());
        }

        if device
            .property_value(PCI_DEV_PATH)
            .map(|v| v.to_str())
            .ok_or_else(|| {
                HardwareEnumerationError::GenericError("Could not decode DEVPATH".to_string())
            })?
            .is_some()
        {
            dmi.board_name = convert_sysattr_to_string("board_name", &device)?.to_string();
            dmi.board_version = convert_sysattr_to_string("board_version", &device)?.to_string();
            dmi.bios_version = convert_sysattr_to_string("bios_version", &device)?.to_string();
            dmi.bios_date = convert_sysattr_to_string("bios_date", &device)?.to_string();
            dmi.product_serial = convert_sysattr_to_string("product_serial", &device)?.to_string();
            dmi.board_serial = convert_sysattr_to_string("board_serial", &device)?.to_string();
            dmi.chassis_serial = convert_sysattr_to_string("chassis_serial", &device)?.to_string();
            dmi.product_name = convert_sysattr_to_string("product_name", &device)?.to_string();
            dmi.sys_vendor = convert_sysattr_to_string("sys_vendor", &device)?.to_string();
        }
    }

    let tpm_ek_certificate = match tpm::get_ek_certificate() {
        Ok(cert) => Some(base64::encode(cert)),
        Err(e) => {
            log::error!("Could not read TPM EK certificate: {:?}", e);
            None
        }
    };

    let dpu_vpd = match arch {
        CpuArchitecture::Aarch64 => match dpu::get_dpu_info() {
            Ok(dpu_data) => Some(dpu_data),
            Err(e) => {
                log::error!("Could not get DPU data: {:?}", e);
                None
            }
        },
        CpuArchitecture::X86_64 => None,
    };

    log::debug!("Discovered Disks - {:?}", disks);
    log::debug!("Discovered CPUs: {:?}", cpus);
    log::debug!("Discovered NICS: {:?}", nics);
    log::debug!("Discovered IBS: {:?}", ibs);
    log::debug!("Discovered NVMES: {:?}", nvmes);
    log::debug!("Discovered DMI: {:?}", dmi);
    log::debug!("Discovered Machine Architecture: {}", info.machine.as_str());
    log::debug!("Discovered DPU: {:?}", dpu_vpd);
    if let Some(cert) = tpm_ek_certificate.as_ref() {
        log::debug!("TPM EK certificate (base64): {}", cert);
    }

    Ok(rpc_discovery::DiscoveryInfo {
        network_interfaces: nics,
        infiniband_interfaces: ibs,
        cpus,
        block_devices: disks,
        nvme_devices: nvmes,
        dmi_data: Some(dmi),
        machine_type: info.machine.as_str().to_owned(),
        tpm_ek_certificate,
        dpu_info: dpu_vpd,
    })
}
