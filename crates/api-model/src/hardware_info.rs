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

//! Describes hardware that is discovered by Forge

use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

use base64::prelude::*;
use carbide_utils::arch::CpuArchitecture;
use carbide_uuid::nvlink::NvLinkDomainId;
use mac_address::{MacAddress, MacParseError};
use serde::{Deserialize, Serialize};

use crate::machine::machine_id::MissingHardwareInfo;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareInfo {
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub infiniband_interfaces: Vec<InfinibandInterface>,
    #[serde(default)]
    pub cpu_info: Vec<CpuInfo>,
    #[serde(default)]
    pub block_devices: Vec<BlockDevice>,
    // This should be called machine_arch, but it's serialized directly in/out of a JSONB field in
    // the DB, so renaming it requires a migration or custom Serialize impl.
    pub machine_type: CpuArchitecture,
    #[serde(default)]
    pub nvme_devices: Vec<NvmeDevice>,
    #[serde(default)]
    pub dmi_data: Option<DmiData>,
    pub tpm_ek_certificate: Option<TpmEkCertificate>,
    #[serde(default)]
    pub dpu_info: Option<DpuData>,
    #[serde(default)]
    pub gpus: Vec<Gpu>,
    #[serde(default)]
    pub memory_devices: Vec<MemoryDevice>,
    #[serde(default)]
    pub tpm_description: Option<TpmDescription>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    #[serde(deserialize_with = "carbide_network::deserialize_mlx_mac")]
    pub mac_address: MacAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfinibandInterface {
    pub guid: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuInfo {
    #[serde(default)]
    pub model: String, // CPU model name
    #[serde(default)]
    pub vendor: String, // CPU vendor name
    #[serde(default)]
    pub sockets: u32, // number of sockets
    #[serde(default)]
    pub cores: u32, // cores per socket
    #[serde(default)]
    pub threads: u32, // threads per socket
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub device_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeDevice {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub firmware_rev: String,
    #[serde(default)]
    pub serial: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmiData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bios_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bios_date: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chassis_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_vendor: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub part_number: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub part_description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub factory_mac_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firmware_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firmware_date: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<LldpSwitchData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpSwitchData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_port: String,
    #[serde(
        default,
        deserialize_with = "deserialize_ip_addr_vec_lossy",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ip_address: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_port: String,
}

fn deserialize_ip_addr_vec_lossy<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?
        .unwrap_or_default()
        .into_iter()
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PciDeviceProperties {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub numa_node: i32,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub slot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gpu {
    pub name: String,
    pub serial: String,
    pub driver_version: String,
    pub vbios_version: String,
    pub inforom_version: String,
    pub total_memory: String,
    pub frequency: String,
    pub pci_bus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_info: Option<GpuPlatformInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuPlatformInfo {
    pub chassis_serial: String,
    pub slot_number: u32,
    pub tray_index: u32,
    pub host_id: u32,
    pub module_id: u32,
    pub fabric_guid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDevice {
    pub size_mb: Option<u32>,
    pub mem_type: Option<String>,
}

/// TPM endorsement key certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmEkCertificate(Vec<u8>);

impl From<Vec<u8>> for TpmEkCertificate {
    fn from(cert: Vec<u8>) -> Self {
        Self(cert)
    }
}

impl TpmEkCertificate {
    /// Returns the binary content of the certificate
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Converts the certificate into a byte array
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for TpmEkCertificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for TpmEkCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(str_value)
            .map_err(|err| Error::custom(err.to_string()))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmDescription {
    pub vendor: String,
    pub firmware_version: String,
    pub tpm_spec: String,
}

#[derive(thiserror::Error, Debug)]
pub enum HardwareInfoError {
    #[error("DPU Info is missing.")]
    MissingDpuInfo,

    #[error("Mac address conversion error: {0}")]
    MacAddressConversionError(#[from] MacParseError),

    #[error("Missing hardware info: {0}")]
    MissingHardwareInfo(#[from] MissingHardwareInfo),
}

impl HardwareInfo {
    /// Returns whether the machine is deemed to be a DPU based on some properties
    pub fn is_dpu(&self) -> bool {
        if self.machine_type != CpuArchitecture::Aarch64 {
            return false;
        }
        self.dmi_data
            .as_ref()
            .is_some_and(|dmi| dmi.board_name.to_lowercase().contains("bluefield"))
    }

    /// This function returns factory_mac_address from dpu_info.
    pub fn factory_mac_address(&self) -> Result<MacAddress, HardwareInfoError> {
        let Some(ref dpu_info) = self.dpu_info else {
            return Err(HardwareInfoError::MissingDpuInfo);
        };

        Ok(MacAddress::from_str(&dpu_info.factory_mac_address)?)
    }

    /// Is this a Dell, Lenovo, etc machine?
    pub fn bmc_vendor(&self) -> bmc_vendor::BMCVendor {
        match self.dmi_data.as_ref() {
            Some(dmi_info) => bmc_vendor::BMCVendor::from_udev_dmi(dmi_info.sys_vendor.as_ref()),
            None => bmc_vendor::BMCVendor::Unknown,
        }
    }

    pub fn all_mac_addresses(&self) -> Vec<MacAddress> {
        self.network_interfaces
            .iter()
            .map(|i| i.mac_address)
            .collect()
    }

    pub fn is_gbx00(&self) -> bool {
        self.dmi_data
            .as_ref()
            .is_some_and(|dmi| dmi.product_name.contains("GB200")) // TODO: for now just do GB200
    }

    pub fn is_dgx_h100(&self) -> bool {
        self.dmi_data
            .as_ref()
            .is_some_and(|dmi| dmi.sys_vendor == "NVIDIA" && dmi.product_name == "DGXH100")
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineInventory {
    pub components: Vec<MachineInventorySoftwareComponent>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MachineInventorySoftwareComponent {
    pub name: String,
    pub version: String,
    pub url: String,
}

impl Display for MachineInventorySoftwareComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.url, self.name, self.version)
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineNvLinkInfo {
    pub domain_uuid: NvLinkDomainId,
    /// Chassis serial from the first GPU `GpuPlatformInfo` at discovery (or operator RPC).
    pub chassis_serial: String,
    pub gpus: Vec<NvLinkGpu>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NvLinkGpu {
    pub tray_index: i32,
    pub slot_id: i32,
    pub device_id: i32, // For GB200s, 1-based index of GPU in compute tray.
    pub guid: u64,
}

impl From<libnmxm::nmxm_model::Gpu> for NvLinkGpu {
    fn from(gpu: libnmxm::nmxm_model::Gpu) -> Self {
        NvLinkGpu {
            tray_index: gpu
                .location_info
                .as_ref()
                .and_then(|info| info.tray_index)
                .unwrap_or_default(),
            slot_id: gpu
                .location_info
                .as_ref()
                .and_then(|info| info.slot_id)
                .unwrap_or_default(),
            device_id: gpu.device_id,
            guid: gpu.device_uid,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const DPU_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/dpu_info.json");
    const DPU_BF3_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/dpu_bf3_info.json");
    const X86_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/x86_info.json");

    #[test]
    fn test_machine_inventory_json_representation() {
        let inventory = MachineInventory {
            components: vec![
                MachineInventorySoftwareComponent {
                    name: "foo".to_string(),
                    version: "1.0".to_string(),
                    url: "".to_string(),
                },
                MachineInventorySoftwareComponent {
                    name: "bar".to_string(),
                    version: "2.0".to_string(),
                    url: "nvidia.com".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&inventory).unwrap();
        assert_eq!(
            json,
            r#"{"components":[{"name":"foo","version":"1.0","url":""},{"name":"bar","version":"2.0","url":"nvidia.com"}]}"#
        );
    }

    #[test]
    fn lldp_switch_data_filters_invalid_management_addresses() {
        let json = r#"{
            "ip_address": [
                "192.0.2.10",
                "not-an-ip",
                "2001:db8::1"
            ]
        }"#;
        let switch: LldpSwitchData = serde_json::from_str(json).unwrap();

        assert_eq!(
            switch.ip_address,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn lldp_switch_data_defaults_null_management_addresses() {
        let switch: LldpSwitchData = serde_json::from_str(r#"{"ip_address":null}"#).unwrap();

        assert!(switch.ip_address.is_empty());
    }

    #[test]
    fn serialize_blockdev() {
        let dev: BlockDevice = serde_json::from_str("{}").unwrap();
        assert_eq!(
            dev,
            BlockDevice {
                model: "".to_string(),
                revision: "".to_string(),
                serial: "".to_string(),
                device_type: "".to_string(),
            }
        );

        let dev1 = BlockDevice {
            model: "disk".to_string(),
            revision: "rev1".to_string(),
            serial: "001".to_string(),
            device_type: "device_type".to_string(),
        };

        let serialized = serde_json::to_string(&dev1).unwrap();
        assert_eq!(
            serialized,
            r#"{"model":"disk","revision":"rev1","serial":"001","device_type":"device_type"}"#
        );
        assert_eq!(
            serde_json::from_str::<BlockDevice>(&serialized).unwrap(),
            dev1
        );
    }

    #[test]
    fn serialize_cpu_info() {
        let cpu_info: CpuInfo = serde_json::from_str("{}").unwrap();
        assert_eq!(
            cpu_info,
            CpuInfo {
                model: "".to_string(),
                vendor: "".to_string(),
                sockets: 0,
                cores: 0,
                threads: 0,
            }
        );

        let cpu_info1 = CpuInfo {
            model: "m1".to_string(),
            vendor: "v1".to_string(),
            sockets: 2,
            cores: 32,
            threads: 64,
        };

        let serialized = serde_json::to_string(&cpu_info1).unwrap();
        assert_eq!(
            serialized,
            "{\"model\":\"m1\",\"vendor\":\"v1\",\"sockets\":2,\"cores\":32,\"threads\":64}"
        );
        assert_eq!(
            serde_json::from_str::<CpuInfo>(&serialized).unwrap(),
            cpu_info1
        );
    }

    #[test]
    fn serialize_pci_dev_properties() {
        let props: PciDeviceProperties = serde_json::from_str("{}").unwrap();
        assert_eq!(
            props,
            PciDeviceProperties {
                vendor: "".to_string(),
                device: "".to_string(),
                path: "".to_string(),
                numa_node: 0,
                description: None,
                slot: None,
            }
        );

        let props1 = PciDeviceProperties {
            vendor: "v1".to_string(),
            device: "d1".to_string(),
            path: "p1".to_string(),
            numa_node: 3,
            description: Some("desc1".to_string()),
            slot: Some("0000:4b:00.0".to_string()),
        };

        let serialized = serde_json::to_string(&props1).unwrap();
        assert_eq!(
            serialized,
            "{\"vendor\":\"v1\",\"device\":\"d1\",\"path\":\"p1\",\"numa_node\":3,\"description\":\"desc1\",\"slot\":\"0000:4b:00.0\"}"
        );
        assert_eq!(
            serde_json::from_str::<PciDeviceProperties>(&serialized).unwrap(),
            props1
        );
    }

    #[test]
    fn deserialize_x86_info() {
        let info = serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap();
        assert!(!info.is_dpu());
    }

    #[test]
    fn deserialize_dpu_info() {
        let info = serde_json::from_slice::<HardwareInfo>(DPU_INFO_JSON).unwrap();
        assert!(info.is_dpu());

        // Make sure deserialize_ch_64 works as expected, where
        // the source dpu_info.json file for this has ch:64 as
        // the mac_address.
        assert_eq!(
            info.network_interfaces[1].mac_address.to_string(),
            "00:00:00:00:00:64"
        );
    }

    #[test]
    fn deserialize_dpu_bf3_info() {
        let info = serde_json::from_slice::<HardwareInfo>(DPU_BF3_INFO_JSON).unwrap();
        assert!(info.is_dpu());
    }

    #[test]
    fn serialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let cert = TpmEkCertificate::from(cert_data.clone());

        let serialized = serde_json::to_string(&cert).unwrap();
        assert_eq!(
            serialized,
            format!("\"{}\"", BASE64_STANDARD.encode(&cert_data))
        );

        // Test also how that the certificate looks right within a Json structure
        #[derive(Serialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let serialized = serde_json::to_string(&OptionalCert { cert: Some(cert) }).unwrap();
        assert_eq!(
            serialized,
            format!("{{\"cert\":\"{}\"}}", BASE64_STANDARD.encode(&cert_data))
        );
    }

    #[test]
    fn deserialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let encoded = BASE64_STANDARD.encode(&cert_data);

        let json = format!("\"{encoded}\"");
        let deserialized: TpmEkCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_bytes(), &cert_data);

        // Test also how that the certificate looks right within a Json structure
        #[derive(Deserialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let json = format!("{{\"cert\":\"{encoded}\"}}");
        let deserialized: OptionalCert = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.cert.as_ref().map(|cert| cert.as_bytes()),
            Some(cert_data.as_slice())
        );
    }
}
