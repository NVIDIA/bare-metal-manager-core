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
use ::utils::cmd::CmdError;
use base64::prelude::*;
use libudev::Device;
use rpc::machine_discovery::MemoryDevice;
use tracing::{error, warn};
use uname::uname;

pub mod dpu;
mod gpu;
pub mod ib;
mod tpm;

const PCI_SUBCLASS: &str = "ID_PCI_SUBCLASS_FROM_DATABASE";
const PCI_DEV_PATH: &str = "DEVPATH";
const PCI_MODEL: &str = "ID_MODEL_FROM_DATABASE";
const PCI_SLOT_NAME: &str = "PCI_SLOT_NAME";
const GPU_PCI_CLASS: &str = "0x030200";
const MEMORY_TYPE: &str = "MEMORY_DEVICE_0_MEMORY_TECHNOLOGY";
const PCI_VENDOR_FROM_DB: &str = "ID_VENDOR_FROM_DATABASE";

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
    #[error("Command error {0}")]
    CmdError(#[from] CmdError),
}

pub struct PciDevicePropertiesExt {
    pub sub_class: String,
    pub pci_properties: rpc_discovery::PciDeviceProperties,
}

pub type HardwareEnumerationResult<T> = Result<T, HardwareEnumerationError>;

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
                "Could not find property {} on device {:?}",
                name,
                device.devpath()
            ))),
            false => Ok(default_value),
        },
        Some(p) => p.to_str().map(|s| s.trim()).ok_or_else(|| {
            HardwareEnumerationError::GenericError(format!(
                "Could not transform os string to string for property {} on device {:?}",
                name,
                device.devpath()
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

fn get_pci_properties_ext(
    device: &Device,
) -> Result<PciDevicePropertiesExt, HardwareEnumerationError> {
    let slot = match device.parent() {
        Some(parent) => convert_property_to_string(PCI_SLOT_NAME, "", &parent)?.to_string(),
        None => String::new(),
    };

    Ok(PciDevicePropertiesExt {
        sub_class: convert_property_to_string(PCI_SUBCLASS, "", device)?.to_string(),
        pci_properties: rpc_discovery::PciDeviceProperties {
            vendor: convert_property_to_string(PCI_VENDOR_FROM_DB, "NO_VENDOR_NAME", device)?
                .to_string(),
            device: convert_property_to_string(PCI_MODEL, "NO_PCI_MODEL", device)?.to_string(),
            path: convert_property_to_string(PCI_DEV_PATH, "", device)?.to_string(),
            numa_node: get_numa_node_from_syspath(device.syspath())?,
            description: Some(
                convert_property_to_string(PCI_MODEL, "NO_PCI_MODEL", device)?.to_string(),
            ),
            slot: Some(slot.to_string()),
        },
    })
}

// discovery all the non-DPU IB devices
pub fn discovery_ibs() -> HardwareEnumerationResult<Vec<rpc_discovery::InfinibandInterface>> {
    let device_debug_log = |device: &Device| {
        tracing::debug!("SysPath - {:?}", device.syspath());
        for p in device.properties() {
            tracing::trace!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            tracing::trace! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    };

    let context = libudev::Context::new()?;
    let mut ibs: Vec<rpc_discovery::InfinibandInterface> = Vec::new();
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("infiniband")?;
    let devices = enumerator.scan_devices()?;
    for device in devices {
        device_debug_log(&device);

        let properties_ext = match get_pci_properties_ext(&device) {
            Ok(properties_ext) => properties_ext,
            Err(e) => {
                tracing::error!(
                    "Failed to enumerate properties of device {:?}: {}",
                    device.devpath(),
                    e
                );
                continue;
            }
        };

        // filter out DPU
        if ib::is_dpu(&properties_ext.pci_properties.device) {
            continue;
        }

        // VPI, IB-only and eth-oly ConnectX devices are here.
        // in case there are eth-only ConnectX devices, we need filter out eth-only.
        if ib::mlnx_ib_capable(&properties_ext) {
            ibs.push(rpc_discovery::InfinibandInterface {
                guid: convert_sysattr_to_string("node_guid", &device)?
                    .to_string()
                    .replace(':', ""),
                pci_properties: Some(properties_ext.pci_properties),
            });
        }
    }
    Ok(ibs)
}

pub fn enumerate_hardware() -> Result<rpc_discovery::DiscoveryInfo, HardwareEnumerationError> {
    let context = libudev::Context::new()?;

    // uname to detect type
    let info = uname().map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;
    let arch = info.machine.parse()?;

    // IBs
    let ibs = discovery_ibs()?;

    // Nics
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("net")?;
    let devices = enumerator.scan_devices()?;

    // mellanox ID_MODEL_ID = "0xa2d6"
    // mellanox ID_VENDOR_FROM_DATABASE = "Mellanox Technologies"
    // mellanox ID_MODEL_FROM_DATABASE = "MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"
    // pci_device_path = DEVPATH = "/devices/pci0000:00/0000:00:1c.4/0000:08:00.0/net/enp8s0f0np0"
    // let fff = devices.map(|device|DiscoveryNic { mac: "".to_string(), dev: "".to_string() });
    let mut nics: Vec<rpc_discovery::NetworkInterface> = Vec::new();

    for device in devices {
        tracing::debug!("SysPath - {:?}", device.syspath());
        for p in device.properties() {
            tracing::trace!("net device property - {:?} - {:?}", p.name(), p.value());
        }
        //for a in device.attributes() {
        //    tracing::trace!("attribute - {:?} - {:?}", a.name(), a.value());
        //}

        if let Ok(pci_subclass) = convert_property_to_string(PCI_SUBCLASS, "", &device) {
            if pci_subclass.eq_ignore_ascii_case("Ethernet controller") {
                let properties_ext = match get_pci_properties_ext(&device) {
                    Ok(properties_ext) => properties_ext,
                    Err(e) => {
                        tracing::error!(
                            "Failed to enumerate properties of device {:?}: {}",
                            device.devpath(),
                            e
                        );
                        continue;
                    }
                };

                // discovery DPU and non ib capable device
                if ib::is_dpu(&properties_ext.pci_properties.device)
                    || !ib::mlnx_ib_capable(&properties_ext)
                {
                    nics.push(rpc_discovery::NetworkInterface {
                        mac_address: convert_udev_to_mac(
                            convert_property_to_string("ID_NET_NAME_MAC", &info.machine, &device)?
                                .to_string(),
                        )?,
                        pci_properties: Some(properties_ext.pci_properties),
                    });
                }
            }
        }
    }

    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info = procfs::CpuInfo::new()
        .map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;

    let mut cpus: Vec<rpc_discovery::Cpu> = Vec::new();
    for cpu_num in 0..cpu_info.num_cores() {
        //tracing::debug!("CPU info: {:?}", cpu_info.get_info(cpu_num));
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
        tracing::debug!("Block device syspath: {:?}", device.syspath());
        //for p in device.properties() {
        //    tracing::trace!("{:?} - {:?}", p.name(), p.value());
        //}

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
        tracing::debug!("NVME device syspath: {:?}", device.syspath());
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
    let mut backup_ram_type = None;
    let mut dmi = rpc_discovery::DmiData::default();
    // We only enumerate the first set of dmi data
    // There is only expected to be a single set, and we don't want to
    // accidentally overwrite it with other data
    if let Some(device) = devices.next() {
        tracing::debug!("DMI device syspath: {:?}", device.syspath());

        // e.g. 'DRAM'. We will use this later if smbios fails.
        backup_ram_type = device
            .property_value(MEMORY_TYPE)
            .map(|v| v.to_string_lossy().to_string());

        if device
            .property_value(PCI_DEV_PATH)
            .map(|v| v.to_str())
            .ok_or_else(|| {
                HardwareEnumerationError::GenericError("Could not decode DEVPATH".to_string())
            })?
            .is_some()
        {
            //for a in device.attributes() {
            //    tracing::debug!("Attribute: {:?} - {:?}", a.name(), a.value());
            //}

            dmi.board_name = convert_sysattr_to_string("board_name", &device)?.to_string();
            dmi.board_version = convert_sysattr_to_string("board_version", &device)?.to_string();
            dmi.bios_version = convert_sysattr_to_string("bios_version", &device)?.to_string();
            dmi.bios_date = convert_sysattr_to_string("bios_date", &device)?.to_string();
            dmi.board_serial = convert_sysattr_to_string("board_serial", &device)?.to_string();
            dmi.chassis_serial = convert_sysattr_to_string("chassis_serial", &device)?.to_string();
            dmi.product_serial = convert_sysattr_to_string("product_serial", &device)?.to_string();
            dmi.product_name = convert_sysattr_to_string("product_name", &device)?.to_string();
            dmi.sys_vendor = convert_sysattr_to_string("sys_vendor", &device)?.to_string();
        }
    }

    let tpm_ek_certificate = match tpm::get_ek_certificate() {
        Ok(cert) => Some(BASE64_STANDARD.encode(cert)),
        Err(e) => {
            tracing::error!("Could not read TPM EK certificate: {:?}", e);
            None
        }
    };

    let dpu_vpd = match dmi.sys_vendor.as_str() {
        "https://www.mellanox.com" => match dpu::get_dpu_info() {
            Ok(dpu_data) => Some(dpu_data),
            Err(e) => {
                tracing::error!("Could not get DPU data: {:?}", e);
                None
            }
        },
        _ => None,
    };

    // Check udev for existing GPUs.  If there are none, then the driver will not be loaded and the tools used to gather information will fail.
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_attribute("class", GPU_PCI_CLASS)?;
    let device_count = enumerator.scan_devices()?.count();

    let gpus = if device_count > 0 {
        gpu::discover_gpus()?
    } else {
        tracing::debug!("No GPUs detected, skipping");
        vec![]
    };

    let mut memory_devices = vec![];
    match smbioslib::table_load_from_device() {
        Ok(smbios_info) => {
            for i in smbios_info.collect::<smbioslib::SMBiosMemoryDevice>() {
                let size_mb = match i.size() {
                    Some(smbioslib::MemorySize::Kilobytes(size)) => size as u32 / 1024,
                    Some(smbioslib::MemorySize::Megabytes(size)) => size as u32,
                    Some(smbioslib::MemorySize::SeeExtendedSize) => {
                        match i.extended_size() {
                            Some(extended_size) => match extended_size {
                                smbioslib::MemorySizeExtended::Megabytes(size) => size,
                                smbioslib::MemorySizeExtended::SeeSize => 0u32, // size was already checked, just return 0
                            },
                            None => 0u32,
                        }
                    }
                    Some(smbioslib::MemorySize::NotInstalled) => 0u32,
                    Some(smbioslib::MemorySize::Unknown) => 0u32,
                    None => 0u32,
                };

                // do not include the module if any of the above conditions ended up with a 0.
                if size_mb == 0 {
                    continue;
                }

                let mem_type = match i.memory_type() {
                    Some(smbioslib::MemoryDeviceTypeData { value, .. }) => {
                        Some(format!("{:?}", value).to_uppercase())
                    }
                    _ => backup_ram_type.clone(),
                };
                memory_devices.push(MemoryDevice {
                    size_mb: Some(size_mb),
                    mem_type,
                });
            }
        }
        Err(err) => {
            warn!("Could not discover host memory using smbios device, using /proc/meminfo: {err}");
            let mut mem = 0u32;
            let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(|e| {
                HardwareEnumerationError::GenericError(format!("Err reading /proc/meminfo: {e}"))
            })?;
            for line in meminfo.lines() {
                // line is "MemTotal:       32572708 kB"
                if line.starts_with("MemTotal:") {
                    mem = line
                        .split_ascii_whitespace()
                        .nth(1)
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or_default();
                    break;
                }
            }
            memory_devices.push(MemoryDevice {
                size_mb: Some(mem / 1024),
                mem_type: backup_ram_type,
            });
        }
    }

    tracing::debug!("Discovered Disks: {:?}", disks);
    if !cpus.is_empty() {
        tracing::debug!("Discovered CPUs[0]: {:?}", cpus[0]);
    }
    tracing::debug!("Discovered NICS: {:?}", nics);
    tracing::debug!("Discovered IBS: {:?}", ibs);
    tracing::debug!("Discovered NVMES: {:?}", nvmes);
    tracing::debug!("Discovered DMI: {:?}", dmi);
    tracing::debug!("Discovered GPUs: {:?}", gpus);
    tracing::debug!("Discovered Machine Architecture: {}", info.machine.as_str());
    tracing::debug!("Discovered DPU: {:?}", dpu_vpd);
    if let Some(cert) = tpm_ek_certificate.as_ref() {
        tracing::debug!("TPM EK certificate (base64): {}", cert);
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
        gpus,
        memory_devices,
    })
}
