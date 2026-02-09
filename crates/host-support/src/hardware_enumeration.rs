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
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::str::Utf8Error;

use ::rpc::machine_discovery as rpc_discovery;
use ::utils::cmd::CmdError;
use ::utils::models::arch::{CpuArchitecture, UnsupportedCpuArchitecture};
use base64::prelude::*;
use libudev::Device;
use procfs::{CpuInfo, FromRead};
use rpc::machine_discovery::MemoryDevice;
use tracing::warn;
use uname::uname;
use utils::{BF2_PRODUCT_NAME, BF3_PRODUCT_NAME};

pub mod dpu;
mod gpu;
mod tpm;

const PCI_SUBCLASS: &str = "ID_PCI_SUBCLASS_FROM_DATABASE";
const PCI_DEV_PATH: &str = "DEVPATH";
const PCI_MODEL: &str = "ID_MODEL_FROM_DATABASE";
const PCI_SLOT_NAME: &str = "PCI_SLOT_NAME";
const MEMORY_TYPE: &str = "MEMORY_DEVICE_0_MEMORY_TECHNOLOGY";
const PCI_VENDOR_FROM_DB: &str = "ID_VENDOR_FROM_DATABASE";
const PCI_DEVICE_ID: &str = "ID_MODEL_ID";
const BF_PRODUCT_NAME_REGEX: &str = "BlueField";
const BF3_CPU_PART: &str = "0xd42";
const NVIDIA_VENDOR_ID: &str = "0x10de";
const NVIDIA_VENDOR_DRIVER: &str = "nvidia";

#[derive(thiserror::Error, Debug)]
pub enum HardwareEnumerationError {
    #[error("Hardware enumeration error: {0}")]
    GenericError(String),
    #[error("Udev failed with error: {0}")]
    UdevError(#[from] libudev::Error),
    #[error("Udev string {0} is not a valid MAC address")]
    InvalidMacAddress(String),
    #[error("{0}")]
    UnsupportedCpuArchitecture(String),
    #[error("Command error {0}")]
    CmdError(#[from] CmdError),
}

pub type HardwareEnumerationResult<T> = Result<T, HardwareEnumerationError>;

// Same as rpc_discovery::CpuInfo but with total thread count before computing threads per socket
struct CpuAccumulator {
    model: String,
    vendor: String,
    sockets: u32,
    cores: u32,
    threads: u32,
}

pub const LINK_TYPE_P1: &str = "LINK_TYPE_P1";

#[derive(Debug)]
pub struct PciDevicePropertiesExt {
    pub sub_class: String,
    pub pci_properties: rpc_discovery::PciDeviceProperties,
    pub device_id: String,
}

impl PciDevicePropertiesExt {
    // This function decides on well known Mellanox PCI ids taken from the https://pci-ids.ucw.cz/read/PC/15b3
    // all BF DPUs start with 0xa2xx or 0xc2xx
    pub fn is_dpu(&self) -> bool {
        self.device_id.starts_with("0xa2") || self.device_id.starts_with("0xc2")
    }

    //pub fn mlnx_ib_capable(device: &str, pci_subclass: &str, vendor: &str) -> bool {
    pub fn mlnx_ib_capable(&self) -> bool {
        // Check only Mellanox port which is presented as a separate network interface
        // ID_PCI_CLASS_FROM_DATABASE='Network controller'
        //   - It is assumption for SUBSYSTEM=[net|infiniband]
        // ID_PCI_SUBCLASS_FROM_DATABASE='Infiniband controller' or 'Ethernet controller'
        //   - Because ports for VPI Mellanox device can be configured in IB(1) or ETH(2) type
        if let Some(slot) = self.pci_properties.slot.as_ref()
            && !slot.is_empty()
            && self
                .pci_properties
                .vendor
                .eq_ignore_ascii_case("Mellanox Technologies")
        {
            return self.sub_class.eq_ignore_ascii_case("Infiniband controller");
        }
        false
    }
}

impl TryFrom<&Device> for PciDevicePropertiesExt {
    type Error = HardwareEnumerationError;
    fn try_from(device: &Device) -> Result<Self, Self::Error> {
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
                slot: Some(slot),
            },
            device_id: convert_property_to_string(PCI_DEVICE_ID, "", device)?.to_string(),
        })
    }
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
    let mut mac = chunks.into_iter().fold(String::new(), |mut s, chunk| {
        let _ = write!(s, "{chunk}:");
        s
    });
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
                "Could not transform os string to string for attribute {name}"
            ))
        }),
    }
}

// NUMA_NODE is not exposed in libudev but the full path to a device is.
// We have to convert from String -> i32 which is full of cases where conversion
// can fail.
fn get_numa_node_from_syspath(syspath: Option<&Path>) -> Result<i32, HardwareEnumerationError> {
    let syspath = syspath
        .ok_or_else(|| HardwareEnumerationError::GenericError("Syspath is None".to_string()))?;
    let numa_node_full_path = syspath.join("device/numa_node");

    let file = fs::File::open(&numa_node_full_path).map_err(|e| {
        HardwareEnumerationError::GenericError(format!(
            "Failed to open {}: {}",
            numa_node_full_path.display(),
            e
        ))
    })?;

    let mut file_reader = BufReader::new(file);
    let mut numa_node_value = String::new();
    file_reader.read_line(&mut numa_node_value).map_err(|e| {
        HardwareEnumerationError::GenericError(format!(
            "Failed to read line from {}: {}",
            numa_node_full_path.display(),
            e
        ))
    })?;

    numa_node_value.trim().parse::<i32>().map_err(|e| {
        HardwareEnumerationError::GenericError(format!(
            "Failed to parse NUMA node value to i32: {e}"
        ))
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

        let properties_ext = match PciDevicePropertiesExt::try_from(&device) {
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

        // SUBSYSTEM=infiniband
        // Skip DPU
        if properties_ext.is_dpu() {
            continue;
        }

        // SUBSYSTEM=infiniband
        // ID_PCI_CLASS_FROM_DATABASE='Network controller'
        //   - It is assumption for SUBSYSTEM=[net|infiniband]
        // ID_PCI_SUBCLASS_FROM_DATABASE='Infiniband controller' or 'Ethernet controller'
        //   - because ports for VPI device can be configured in IB(1) or ETH(2) types
        if properties_ext.mlnx_ib_capable() {
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

impl From<&CpuAccumulator> for rpc_discovery::CpuInfo {
    fn from(src: &CpuAccumulator) -> Self {
        let threads_per_socket = src.threads.checked_div(src.sockets).unwrap_or(0);

        rpc_discovery::CpuInfo {
            model: src.model.clone(),
            vendor: src.vendor.clone(),
            sockets: src.sockets,
            cores: src.cores,
            threads: threads_per_socket,
        }
    }
}

pub fn aggregate_cpus(cpus: &[rpc_discovery::Cpu]) -> Vec<rpc_discovery::CpuInfo> {
    //
    //  Process CPU data
    //

    // This logic is ported from forge-cloud/cloud-backend. The handling of multiple CPU models on
    // a single machine is possibly misleading, but possibly it handles some future build, and it
    // accumulates all the info in any case. This function should return a vector with only one
    // CpuInfo.
    //
    // Number of unique sockets is cpu count.
    // Highest core number + 1 is the number of cores per socket.
    // Highest Number + 1 is total thread count, which
    // we'll divide by number of sockets later.

    let mut cpu_map = HashMap::<String, CpuAccumulator>::new();
    let mut cpu_socket_set = HashSet::<(String, u32)>::new();
    // Go through the CPUs listed in the hardware info and accumulate the details.
    for cpu in cpus.iter() {
        match cpu_map.get_mut(&cpu.model) {
            None => {
                // Insert into the socket map so we don't keep incrementing cpu count
                // as we look for threads and cores.
                cpu_socket_set.insert((cpu.model.clone(), cpu.socket));

                cpu_map.insert(
                    cpu.model.clone(),
                    CpuAccumulator {
                        model: cpu.model.clone(),
                        vendor: cpu.vendor.clone(),
                        sockets: 1,
                        cores: cpu.core + 1,
                        threads: cpu.number + 1,
                    },
                );
            }
            Some(accumulator) => {
                // If the socket hasn't been seen yet (i.e., if it's new to the set),
                // increment the cpu count.
                if cpu_socket_set.insert((cpu.model.clone(), cpu.socket)) {
                    accumulator.sockets += 1;
                }

                let core_count = cpu.core + 1;
                if core_count > accumulator.cores {
                    accumulator.cores = core_count;
                }

                let thread_count = cpu.number + 1;
                if thread_count > accumulator.threads {
                    accumulator.threads = thread_count;
                }
            }
        };
    }

    let mut values: Vec<&CpuAccumulator> = cpu_map.values().collect();
    values.sort_by_key(|v| &v.model);
    values
        .into_iter()
        .map(rpc_discovery::CpuInfo::from)
        .collect()
}

// `lscpu` fields in exact case-sensitive form
// if present, these fields can be assumed to have these standard names
const LSCPU_VENDOR: &str = "Vendor ID";
const LSCPU_MODEL: &str = "Model name";
const LSCPU_SOCKETS: &str = "Socket(s)";
const LSCPU_CORES_PER_SOCKET: &str = "Core(s) per socket";
const LSCPU_THREADS_PER_CORE: &str = "Thread(s) per core";

fn get_lscpu_info() -> HashMap<&'static str, String> {
    let keys = [
        LSCPU_VENDOR,
        LSCPU_MODEL,
        LSCPU_SOCKETS,
        LSCPU_CORES_PER_SOCKET,
        LSCPU_THREADS_PER_CORE,
    ];

    let mut lscpu_info: HashMap<&'static str, String> = HashMap::new();
    let output = Command::new("lscpu").output();

    if let Ok(out) = output
        && let Ok(text) = std::str::from_utf8(&out.stdout)
    {
        for line in text.lines() {
            // `lscpu` output format is "  <key>:   <value>" with
            // various levels of indentation before <key>
            if let Some((k, v)) = line.split_once(':') {
                let trimmed_key = k.trim();
                if let Some(key) = keys.iter().find(|&&s| s == trimmed_key).copied() {
                    lscpu_info.insert(key, v.trim().to_string());
                }
            }
        }
    }

    lscpu_info
}

fn can_parse_int(s: &str) -> bool {
    if let Some(hex) = s.strip_prefix("0x") {
        i32::from_str_radix(hex, 16).is_ok()
    } else {
        s.parse::<i32>().is_ok()
    }
}

fn get_cpu_info(
    lscpu_info: &HashMap<&'static str, String>,
    proc_cpu_info: rpc_discovery::CpuInfo,
) -> rpc_discovery::CpuInfo {
    // Prefer vendor from `lscpu` only if the value from procfs is an
    // unmapped integer.
    let preferred_vendor = if can_parse_int(&proc_cpu_info.vendor) {
        lscpu_info.get(LSCPU_VENDOR).cloned()
    } else {
        None
    };

    // Prefer model from `lscpu` only if the value from procfs is an
    // unmapped integer.
    let preferred_model = if can_parse_int(&proc_cpu_info.model) {
        lscpu_info.get(LSCPU_MODEL).cloned()
    } else {
        None
    };

    // Prefer topology from `lscpu` only if it completely specifies sockets,
    // cores, and threads (all or nothing).
    let (preferred_sockets, preferred_cores, preferred_threads) = match (
        lscpu_info
            .get(LSCPU_SOCKETS)
            .and_then(|s| s.parse::<u32>().ok()),
        lscpu_info
            .get(LSCPU_CORES_PER_SOCKET)
            .and_then(|s| s.parse::<u32>().ok()),
        lscpu_info
            .get(LSCPU_THREADS_PER_CORE)
            .and_then(|s| s.parse::<u32>().ok()),
    ) {
        (Some(s), Some(c), Some(t)) => (Some(s), Some(c), Some(c * t)),
        _ => (None, None, None),
    };

    rpc_discovery::CpuInfo {
        vendor: preferred_vendor.unwrap_or(proc_cpu_info.vendor),
        model: preferred_model.unwrap_or(proc_cpu_info.model),
        sockets: preferred_sockets.unwrap_or(proc_cpu_info.sockets),
        cores: preferred_cores.unwrap_or(proc_cpu_info.cores),
        threads: preferred_threads.unwrap_or(proc_cpu_info.threads),
    }
}

pub fn enumerate_hardware() -> Result<rpc_discovery::DiscoveryInfo, HardwareEnumerationError> {
    let context = libudev::Context::new()?;

    // uname to detect type
    let info = uname().map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;
    let arch = info
        .machine
        .parse()
        .map_err(|e: UnsupportedCpuArchitecture| {
            HardwareEnumerationError::UnsupportedCpuArchitecture(e.0)
        })?;

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
        let sys_path = device.syspath();
        tracing::debug!("SysPath - {:?}", sys_path);
        for p in device.properties() {
            tracing::trace!("net device property - {:?} - {:?}", p.name(), p.value());
        }
        //for a in device.attributes() {
        //    tracing::trace!("attribute - {:?} - {:?}", a.name(), a.value());
        //}

        if let Ok(pci_subclass) = convert_property_to_string(PCI_SUBCLASS, "", &device)
            && pci_subclass.eq_ignore_ascii_case("Ethernet controller")
        {
            let properties_ext = match PciDevicePropertiesExt::try_from(&device) {
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

            tracing::trace!("properties: {:?}", properties_ext);

            // discovery DPU and non ib capable device
            // Note:
            //   Probably current logic does not allow to detect non DPU network interfaces
            //   with following properties
            //     SUBSYSTEM=infiniband
            //     ID_PCI_CLASS_FROM_DATABASE='Network controller'
            //     ID_PCI_SUBCLASS_FROM_DATABASE='Ethernet controller'
            if properties_ext.is_dpu() || !properties_ext.mlnx_ib_capable() {
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

    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info = {
        let file = File::open("/proc/cpuinfo")
            .map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;
        let reader = BufReader::new(file);
        CpuInfo::from_read(reader)
            .map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?
    };

    let cpu_part = cpu_info
        .get_info(0)
        .and_then(|info| info.get("CPU part").copied())
        .map(str::to_string)
        .unwrap_or_default();

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
            CpuArchitecture::Unknown => {
                tracing::error!(
                    cpu_num,
                    arch = info.machine,
                    "CPU has unsupported architecture. Ignoring."
                );
            }
        }
    }

    let mut cpu_aggregation = aggregate_cpus(&cpus);
    if let CpuArchitecture::Aarch64 = arch {
        let lscpu_info = get_lscpu_info();
        cpu_aggregation = cpu_aggregation
            .into_iter()
            .map(|elem| get_cpu_info(&lscpu_info, elem))
            .collect();
    }

    // disks
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("block")?;
    let devices = enumerator.scan_devices()?;

    let mut disks: Vec<rpc_discovery::BlockDevice> = Vec::new();

    for device in devices {
        // tracing::info!("Block device syspath: {:?}", device.syspath());
        // for p in device.properties() {
        //     tracing::info!("prop:{:?} - {:?}", p.name(), p.value());
        // }
        // for p in device.attributes() {
        //     tracing::info!("attr:{:?} - {:?}", p.name(), p.value());
        // }

        // skip the device if its hidden
        if convert_sysattr_to_string("hidden", &device).is_ok_and(|v| v == "1") {
            tracing::info!(
                "Ignoring hidden device {}",
                device
                    .syspath()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
            );
            continue;
        }

        // skip the device if its removable
        if convert_sysattr_to_string("removable", &device).is_ok_and(|v| v != "0") {
            tracing::info!(
                "Ignoring removable device {}",
                device
                    .syspath()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
            );
            continue;
        }

        if convert_property_to_string(PCI_DEV_PATH, "", &device)
            .is_ok_and(|v| v.contains("virtual"))
        {
            tracing::info!(
                "Ignoring virtual device {}",
                device
                    .syspath()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
            );
            continue;
        }

        disks.push(rpc_discovery::BlockDevice {
            model: convert_property_to_string("ID_MODEL", "NO_MODEL", &device)?.to_string(),
            revision: convert_property_to_string("ID_REVISION", "NO_REVISION", &device)?
                .to_string(),
            serial: convert_property_to_string("ID_SERIAL_SHORT", "NO_SERIAL", &device)?
                .to_string(),
            device_type: convert_property_to_string("DEVTYPE", "NO_TYPE", &device)?.to_string(),
        });
    }

    // Nvme
    let mut enumerator = libudev::Enumerator::new(&context)?;
    enumerator.match_subsystem("nvme")?;
    let devices = enumerator.scan_devices()?;

    let mut nvmes: Vec<rpc_discovery::NvmeDevice> = Vec::new();

    for device in devices {
        // tracing::info!("NVME device syspath: {:?}", device.syspath());
        // for p in device.properties() {
        //     tracing::info!("prop:{:?} - {:?}", p.name(), p.value());
        // }
        // for p in device.attributes() {
        //     tracing::info!("attr:{:?} - {:?}", p.name(), p.value());
        // }

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
                serial: convert_sysattr_to_string("serial", &device)?
                    .trim()
                    .to_string(),
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
            dmi.product_serial = convert_sysattr_to_string("product_serial", &device)?.to_string();
            dmi.product_name = convert_sysattr_to_string("product_name", &device)?.to_string();
            if cpu_part == BF3_CPU_PART && dmi.product_name == BF2_PRODUCT_NAME {
                tracing::info!(
                    "Overriding product name {} with {}",
                    dmi.product_name,
                    BF3_PRODUCT_NAME
                );
                dmi.product_name = BF3_PRODUCT_NAME.to_owned();
            }
            dmi.sys_vendor = convert_sysattr_to_string("sys_vendor", &device)?.to_string();

            // TODO (spyda): reach out to the NBU team. We recently found DPUs that reports a
            // serial number for board_serial instead of what was previously found: "Unspecified Base Board Serial Number".
            // Figure out a longer term strategy to use all three serial numbers. Keeping the commented out code below for future reference.
            // Possible Values for dmi.product_name: BlueField SoC (BF2), BlueField-3 SmartNIC Main Card (BF3), BlueField-3 DPU (BF3)
            if dmi.product_name.contains(BF_PRODUCT_NAME_REGEX) {
                dmi.board_serial = utils::DEFAULT_DPU_DMI_BOARD_SERIAL_NUMBER.to_string();
                dmi.chassis_serial = utils::DEFAULT_DPU_DMI_CHASSIS_SERIAL_NUMBER.to_string();
            } else {
                dmi.board_serial = convert_sysattr_to_string("board_serial", &device)?.to_string();
                dmi.chassis_serial =
                    convert_sysattr_to_string("chassis_serial", &device)?.to_string();
            }
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
        "https://www.mellanox.com" | "Nvidia" => match dpu::get_dpu_info() {
            Ok(dpu_data) => Some(dpu_data),
            Err(e) => {
                tracing::error!("Could not get DPU data: {:?}", e);
                None
            }
        },
        _ => None,
    };

    let mut enumerator = libudev::Enumerator::new(&context)?;
    // It is currently assumed all GPUs are from vendor nvidia and use the nvidia driver
    enumerator.match_attribute("vendor", NVIDIA_VENDOR_ID)?;
    enumerator.match_attribute("driver", NVIDIA_VENDOR_DRIVER)?;

    let device_count = enumerator.scan_devices()?.count();

    // If there are no GPUs present on the host we do not want to run nvidia-smi as it will fail
    let gpus = if device_count > 0 {
        gpu::get_nvidia_smi_data()?
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
                        Some(format!("{value:?}").to_uppercase())
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
        cpu_info: cpu_aggregation,
        block_devices: disks,
        nvme_devices: nvmes,
        dmi_data: Some(dmi),
        machine_type: arch.to_string(),
        machine_arch: Some(arch.into()),
        tpm_ek_certificate,
        dpu_info: dpu_vpd,
        gpus,
        memory_devices,
        tpm_description: None,
        attest_key_info: None,
        // TODO: Remove when there's no longer a need to handle the old topology format
        ..Default::default()
    })
}
