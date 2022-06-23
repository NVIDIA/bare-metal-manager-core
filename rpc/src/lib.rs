//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!

use mac_address::{MacAddress, MacParseError};
use prost::Message;
use serde::{Serialize, Serializer};
use std::convert::From;
use std::convert::TryFrom;
use std::fmt::Display;
use std::str::FromStr;

pub use prost_types::Timestamp;
use serde::ser::SerializeStruct;

use forge::v0::machine_discovery_info::DiscoveryData;
use forge::v0::Domain;
use forge::v0::MachineDiscoveryInfo;
use forge::v0::MachineEvent;
use forge::v0::MachineInterface;
use forge::v0::Uuid;
use machine_discovery::v0::BlockDevice;
use machine_discovery::v0::Cpu;
use machine_discovery::v0::DiscoveryInfo;
use machine_discovery::v0::NetworkInterface;
use machine_discovery::v0::PciDeviceProperties;

use rust_fsm::*;

// In order for CLion to grok the generated files, we need to use include! instead of
// tonic's built in include. To include the proto build in CLion, ensure that the experimental
// `org.rust.cargo.evaluate.build.scripts` flag is enabled.
include!("generated/mod.rs");
pub const REFLECTION_SERVICE_DESCRIPTOR: &[u8] = include_bytes!("generated/forge.v0.bin");

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
            DiscoveryData::InfoV0(ref d) => {
                serializer.serialize_newtype_variant("DiscoveryData", 0, "InfoV0", &d)
            }
        }
    }
}

impl Serialize for DiscoveryInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DiscoveryInfo", 3)?;
        state.serialize_field("network_interfaces", &self.network_interfaces)?;
        state.serialize_field("cpus", &self.cpus)?;
        state.serialize_field("block_devices", &self.block_devices)?;
        state.end()
    }
}

impl Serialize for NetworkInterface {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("NetworkInterface", 3)?;

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
        state.end()
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Uuid {
        Uuid {
            value: uuid.to_hyphenated().to_string(),
        }
    }
}

impl TryFrom<Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl TryFrom<&Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl Display for Uuid {
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
    Assigned => {Unassign => Ready, Fail => Broken},
    Broken(Recommission) => Tested,
    Decommissioned => {Recommission => Tested, Release => New},
}
