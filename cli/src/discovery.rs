use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::Utf8Error;

use libudev::{Context, Device};
use uname::uname;

use ::rpc::machine_discovery::v0 as rpc_discovery;
use cli::{CarbideClientError, CarbideClientResult};
use rpc::forge::v0 as rpc;

pub struct Discovery {}

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
        Some(p) => p.to_str().ok_or_else(|| {
            CarbideClientError::GenericError(format!(
                "Could not transform os string to string for property {}",
                name
            ))
        }),
    };
}

// NUMA_NODE is not exposed in libudev but the full path to a device is.
// We have to convert from String -> i32 which is full of cases where conversion
// can fail. Rather than cause the client to error out during discovery, we use the
// largest i32 as an indicator that the host is likely in a bad state as there is no
// valid reason why the `numa_node` file on the /proc filesystem would contain garbage
fn get_numa_node_from_syspath(syspath: Option<&Path>) -> CarbideClientResult<i32> {
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
                    Err(e) => return Err(CarbideClientError::GenericError(e.to_string())),
                };
                return res;
            }
        };
        Ok(result)
    } else {
        Ok(NUMA_NODE_ESCAPE_HATCH)
    }
}

pub fn get_machine_details(
    context: &Context,
    uuid: &str,
) -> CarbideClientResult<rpc::MachineDiscoveryInfo> {
    // uname to detect type
    let info = uname().map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    log::debug!("{:?}", info);
    // Nics
    let mut enumerator = libudev::Enumerator::new(context)
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    enumerator
        .match_subsystem("net")
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    let devices = enumerator
        .scan_devices()
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    // mellanox ID_MODEL_ID = "0xa2d6"
    // mellanox ID_VENDOR_ID = "0x15b3"
    // mellanox ID_MODEL_FROM_DATABASE = "MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"
    // pci_device_path = DEVPATH = "/devices/pci0000:00/0000:00:1c.4/0000:08:00.0/net/enp8s0f0np0"
    // let fff = devices.map(|device|DiscoveryNic { mac: "".to_string(), dev: "".to_string() });
    let mut nics: Vec<rpc_discovery::NetworkInterface> = Vec::new();

    for device in devices {
        log::debug!("SysPath - {:?}", device.syspath());
        for p in device.properties() {
            log::debug!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::debug! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }

        if device
            .property_value("ID_PCI_SUBCLASS_FROM_DATABASE")
            .filter(|v| v.eq_ignore_ascii_case("Ethernet controller"))
            .is_some()
        {
            nics.push(rpc_discovery::NetworkInterface {
                mac_address: convert_udev_to_mac(
                    convert_property_to_string("ID_NET_NAME_MAC", &info.machine, &device)?
                        .to_string(),
                )?,
                pci_properties: Some(rpc_discovery::PciDeviceProperties {
                    vendor: convert_property_to_string("ID_VENDOR_ID", "", &device)?.to_string(),
                    device: convert_property_to_string("ID_MODEL_ID", "", &device)?.to_string(),
                    path: convert_property_to_string("DEVPATH", "", &device)?.to_string(),
                    numa_node: get_numa_node_from_syspath(device.syspath())?,
                    description: Some(
                        convert_property_to_string("ID_MODEL_FROM_DATABASE", "", &device)?
                            .to_string(),
                    ),
                }),
            });
        }
    }
    // on x86 physical_package_id == physical socket number
    // package_cpu_list = list of CPU's sharing the same physical_package_id
    // core_cpus_list = list of CPU's within the same core
    // key name in attribute of 'nodeX' indicates the numa node the CPU is part of
    let mut enumerator = libudev::Enumerator::new(context)
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    enumerator
        .match_subsystem("cpu")
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    let devices = enumerator
        .scan_devices()
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    for device in devices {
        log::debug!("Syspath - {:?}", device.syspath());
        for p in device.properties() {
            log::debug!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::debug! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    }
    let mut enumerator = libudev::Enumerator::new(context)
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    enumerator
        .match_subsystem("node")
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    let devices = enumerator
        .scan_devices()
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    for device in devices {
        log::debug!("Syspath - {:?}", device.syspath());
        for p in device.properties() {
            log::debug!("Property - {:?} - {:?}", p.name(), p.value());
        }
        for a in device.attributes() {
            log::debug! {"attribute - {:?} - {:?}", a.name(), a.value()}
        }
    }
    // cpus
    // TODO(baz): make this work with udev one day... I tried and it gave me useless information on the cpu subsystem
    let cpu_info =
        procfs::CpuInfo::new().map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    let mut cpus: Vec<rpc_discovery::Cpu> = Vec::new();
    for cpu_num in 0..cpu_info.num_cores() {
        log::debug!("{:?}", cpu_info.get_info(cpu_num));
        match info.machine.as_str() {
            "aarch64" => {
                cpus.push(rpc_discovery::Cpu {
                    vendor: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("CPU implementer"))
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
                                "Could not get arm vendor name".to_string(),
                            )
                        })?
                        .to_string(),
                    model: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("CPU variant"))
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
                                "Could not get arm model name".to_string(),
                            )
                        })?
                        .to_string(),
                    frequency: cpu_info
                        .get_info(cpu_num)
                        .and_then(|mut m| m.remove("BogoMIPS"))
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
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
            "x86_64" => {
                cpus.push(rpc_discovery::Cpu {
                    vendor: cpu_info
                        .vendor_id(cpu_num)
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
                                "Could not get vendor name".to_string(),
                            )
                        })?
                        .to_string(),
                    model: cpu_info
                        .model_name(cpu_num)
                        .ok_or_else(|| {
                            CarbideClientError::GenericError("Could not get model name".to_string())
                        })?
                        .to_string(),
                    frequency: cpu_info
                        .get_info(cpu_num)
                        .ok_or_else(|| {
                            CarbideClientError::GenericError("Could not get cpu info".to_string())
                        })?
                        .get("cpu MHz")
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
                                "Could not get cpu MHz field".to_string(),
                            )
                        })?
                        .to_string(),
                    number: cpu_num as u32,
                    socket: cpu_info.physical_id(cpu_num).ok_or_else(|| {
                        CarbideClientError::GenericError("Could not get cpu info".to_string())
                    })?,
                    core: cpu_info
                        .get_info(cpu_num)
                        .ok_or_else(|| {
                            CarbideClientError::GenericError("Could not get cpu info".to_string())
                        })?
                        .get("core id")
                        .map(|c| c.parse::<u32>().unwrap_or(0))
                        .ok_or_else(|| {
                            CarbideClientError::GenericError(
                                "Could not get cpu core id field".to_string(),
                            )
                        })?,
                    node: 0,
                });
            }
            a => {
                return Err(CarbideClientError::GenericError(format!(
                    "Could not find a valid architecture: {}",
                    a
                )))
            }
        }
    }

    // disks
    let mut enumerator = libudev::Enumerator::new(context)
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    enumerator
        .match_subsystem("block")
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
    let devices = enumerator
        .scan_devices()
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    let mut disks: Vec<rpc_discovery::BlockDevice> = Vec::new();

    for device in devices {
        log::debug!("{:?}", device.syspath());
        for p in device.properties() {
            log::debug!("{:?} - {:?}", p.name(), p.value());
        }

        if device
            .property_value("DEVPATH")
            .map(|v| v.to_str())
            .ok_or_else(|| {
                CarbideClientError::GenericError("Could not decode DEVPATH".to_string())
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

    log::debug!("Disks sent to carbide - {:?}", disks);
    log::debug!("CPUs sent to carbide - {:?}", cpus);
    log::debug!("NICS send to carbide - {:?}", nics);

    let rpc_uuid: rpc::Uuid = uuid::Uuid::parse_str(uuid)
        .map(|m| m.into())
        .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

    Ok(rpc::MachineDiscoveryInfo {
        machine_id: Some(rpc_uuid),
        discovery_data: Some(
            ::rpc::forge::v0::machine_discovery_info::DiscoveryData::InfoV0(
                rpc_discovery::DiscoveryInfo {
                    network_interfaces: nics,
                    cpus,
                    block_devices: disks,
                    machine_type: info.machine.as_str().to_owned(),
                },
            ),
        ),
    })
}

impl Discovery {
    pub async fn run(listen: String, uuid: &str) -> CarbideClientResult<()> {
        let context = libudev::Context::new().map_err(CarbideClientError::from)?;
        let info = get_machine_details(&context, uuid)?;
        let mut client = rpc::forge_client::ForgeClient::connect(listen.clone()).await?;
        let request = tonic::Request::new(info);
        client.discover_machine(request).await?;
        //if let Err(x) = ipmi::update_ipmi_creds(listen, uuid).await {
        //    log::error!("Error while setting up IPMI. {}", x.to_string());
        //}

        Ok(())
    }
}
