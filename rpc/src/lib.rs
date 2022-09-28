//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!

use std::convert::From;
use std::convert::TryFrom;
use std::fmt::Display;
use std::str::FromStr;

use mac_address::{MacAddress, MacParseError};
use prost::Message;
pub use prost_types::Timestamp;
use rust_fsm::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

pub use crate::protos::forge::{
    self, machine_discovery_info::DiscoveryData, Domain, MachineDiscoveryInfo, MachineEvent,
    MachineInterface, Uuid,
};
pub use crate::protos::machine_discovery::{
    self, BlockDevice, Cpu, DiscoveryInfo, NetworkInterface, PciDeviceProperties,
};

pub mod protos;

pub const REFLECTION_SERVICE_DESCRIPTOR: &[u8] = include_bytes!("protos/forge.bin");

pub fn get_encoded_reflection_service_fd() -> Vec<u8> {
    let mut expected = Vec::new();
    prost_types::FileDescriptorSet::decode(REFLECTION_SERVICE_DESCRIPTOR)
        .expect("decode reflection service file descriptor set")
        .file[0]
        .encode(&mut expected)
        .expect("encode reflection service file descriptor");
    expected
}

impl Serialize for MachineDiscoveryInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MachineDiscoveryInfo", 2)?;
        state.serialize_field("machine_id", &self.machine_id)?;
        state.serialize_field("discovery_data", &self.discovery_data)?;
        state.end()
    }
}

impl Serialize for DiscoveryData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            DiscoveryData::Info(ref d) => {
                serializer.serialize_newtype_variant("DiscoveryData", 0, "Info", &d)
            }
        }
    }
}

impl Serialize for DiscoveryInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DiscoveryInfo", 4)?;
        state.serialize_field("network_interfaces", &self.network_interfaces)?;
        state.serialize_field("cpus", &self.cpus)?;
        state.serialize_field("block_devices", &self.block_devices)?;
        state.serialize_field("machine_type", &self.machine_type)?;
        state.end()
    }
}

impl Serialize for NetworkInterface {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("NetworkInterface", 2)?;

        state.serialize_field("mac_address", &self.mac_address)?;
        state.serialize_field("pci_properties", &self.pci_properties)?;
        state.end()
    }
}

impl Serialize for PciDeviceProperties {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PciDeviceProperties", 5)?;
        state.serialize_field("vendor", &self.vendor)?;
        state.serialize_field("device", &self.device)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("numa_node", &self.numa_node)?;
        state.serialize_field("description", &self.description)?;
        state.end()
    }
}

impl Serialize for BlockDevice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("block_device", 3)?;
        state.serialize_field("serial", &self.serial)?;
        state.serialize_field("model", &self.model)?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl Serialize for Cpu {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MachineDiscoveryCpu", 7)?;

        state.serialize_field("frequency", &self.frequency)?;
        state.serialize_field("number", &self.number)?;
        state.serialize_field("model", &self.model)?;
        state.serialize_field("vendor", &self.vendor)?;
        state.serialize_field("core", &self.core)?;
        state.serialize_field("node", &self.node)?;
        state.serialize_field("socket", &self.node)?;
        state.end()
    }
}

impl Serialize for MachineEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("MachineEvent", 5)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field("machine_id", &self.machine_id)?;
        state.serialize_field("event", &self.event)?;
        state.serialize_field("time", &self.time.as_ref().map(|ts| ts.seconds))?;

        state.end()
    }
}

impl Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Domain", 4)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("created", &self.created.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("updated", &self.updated.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("deleted", &self.updated.as_ref().map(|ts| ts.seconds))?;
        state.end()
    }
}

impl From<uuid::Uuid> for forge::Uuid {
    fn from(uuid: uuid::Uuid) -> forge::Uuid {
        forge::Uuid {
            value: uuid.hyphenated().to_string(),
        }
    }
}

impl TryFrom<forge::Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl TryFrom<&forge::Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl Display for forge::Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match uuid::Uuid::try_from(self) {
            Ok(uuid) => write!(f, "{}", uuid),
            Err(err) => write!(f, "<uuid error: {}>", err),
        }
    }
}

impl MachineInterface {
    pub fn parsed_mac_address(&self) -> Result<Option<MacAddress>, MacParseError> {
        Ok(Some(MacAddress::from_str(&self.mac_address)?))
    }
}

state_machine! {
    derive(Debug)
    pub MachineStateMachine(Init)

    Init(Discover) => New,
    New => {Adopt => Adopted, Fail => Broken,},
    Adopted => {Test => Tested, Fail => Broken,},
    Tested => {Commission => Ready, Fail => Broken,},
    Ready => {Assign => Assigned, Decommission => Decommissioned, Fail => Broken,},
    Assigned => {Unassign => Reset, Fail => Broken},
    Reset => {Cleanup => Ready, Fail => Broken},
    Broken(Recommission) => Tested,
    Decommissioned => {Recommission => Tested, Release => New},
}

state_machine! {
    derive(Debug)
    pub VpcResourceStateMachine(Init)

    // initial state is New and generated when the Carbide resource (Machine, MachineInterface etc)
    // is successfully persisted to database
    //
    // From New, submit to forge-vpc the resource (CRD) that needs to be created in forge-vpc
    //    e.g. ResourceGroup, ManagedResource, Leaf
    // Just before we submit the request to forge-vpc  to the Submitting state
    // When forge-vpc ACK's our resource creation submission, we move t Accepted
    // After Accepted we move to "WaitingForVpc" while forge-vpc completes the necessary work
    //
    // In addition to a background job that is spawned to handle creation of forge-vpc resources
    // an additional job will spawn to handle retrieving status from forge-vpc and
    // updating the state for the resource in in forge DB.
    // once forge-vpc reports the new resource as successfully created, we move to "Ready" state
    // IF any steps alongs the way fails, move to 'Broken' state and setup to retry again.

    Init(Initialize) => New,
    New => { Submit => Submitting, Fail => Broken,},
    Submitting => { Accept => Accepted, Fail => Broken, },
    Accepted => { Wait => WaitingForVpc, Fail => Broken,},
    WaitingForVpc => { VpcSuccess => Ready, Fail => Broken, },
    Broken(Recommission) => Init,
}

#[cfg(test)]
mod test {
    use crate::{
        BlockDevice, Cpu, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo, NetworkInterface,
        PciDeviceProperties,
    };

    fn create_test_cpu() -> Cpu {
        Cpu {
            vendor: "vendor".to_string(),
            model: "model".to_string(),
            frequency: "frequency".to_string(),
            number: 1_u32,
            socket: 1,
            core: 1,
            node: 0,
        }
    }

    fn create_test_block_device() -> BlockDevice {
        BlockDevice {
            model: "model".to_string(),
            revision: "revision".to_string(),
            serial: "serial".to_string(),
        }
    }

    fn create_test_pci_device_properties() -> PciDeviceProperties {
        PciDeviceProperties {
            vendor: "vendor".to_string(),
            device: "device".to_string(),
            path: "path".to_string(),
            numa_node: 1,
            description: Some("description".to_string()),
        }
    }

    fn create_test_network_interface() -> NetworkInterface {
        NetworkInterface {
            mac_address: "mac_address".to_string(),
            pci_properties: Some(create_test_pci_device_properties()),
        }
    }

    fn create_test_discovery_info() -> DiscoveryInfo {
        DiscoveryInfo {
            network_interfaces: vec![create_test_network_interface()],
            cpus: vec![create_test_cpu()],
            block_devices: vec![create_test_block_device()],
            machine_type: "machine_type".to_string(),
        }
    }

    fn create_test_discovery_data_info() -> DiscoveryData {
        DiscoveryData::Info(create_test_discovery_info())
    }

    fn create_test_machine_discovery_info() -> MachineDiscoveryInfo {
        let rpc_uuid_str = uuid::Uuid::new_v4().to_string();
        let rpc_uuid: crate::Uuid = uuid::Uuid::parse_str(rpc_uuid_str.as_str()).unwrap().into();

        MachineDiscoveryInfo {
            machine_id: Some(rpc_uuid),
            discovery_data: Some(create_test_discovery_data_info()),
        }
    }

    #[test]
    pub fn machine_discovery_info_there_and_back_again() {
        let machine_discovery_info = create_test_machine_discovery_info();

        let serialized_string = serde_json::to_string(&machine_discovery_info).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&serialized_string).unwrap();

        let info = &json_value["discovery_data"];
        let discovery_data = &info["Info"];
        let machine_type = &discovery_data["machine_type"];
        let machine_type = machine_type.as_str().unwrap();

        assert_eq!("machine_type", machine_type);
        // we should also be testing more than one field coming back
    }
}
