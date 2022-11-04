/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
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
use serde::Serialize;

pub use crate::protos::forge::{
    self, machine_credentials_update_request::CredentialPurpose,
    machine_discovery_info::DiscoveryData, Domain, Instance, InstanceList, InstanceSubnet, Machine,
    MachineAction, MachineCleanupInfo, MachineDiscoveryInfo, MachineEvent, MachineInterface,
    MachineList, Uuid,
};
pub use crate::protos::machine_discovery::{
    self, BlockDevice, Cpu, DiscoveryInfo, DmiDevice, NetworkInterface, NvmeDevice,
    PciDeviceProperties,
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

#[derive(Debug, Clone, Copy)]
pub struct DiscriminantError(i32);

impl TryFrom<i32> for CredentialPurpose {
    type Error = DiscriminantError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::Hbn as i32 => Ok(Self::Hbn),
            x if x == Self::LoginUser as i32 => Ok(Self::LoginUser),
            _ => Err(DiscriminantError(value)),
        }
    }
}

impl TryFrom<i32> for MachineAction {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            x if x == MachineAction::Unknown as i32 => Ok(MachineAction::Unknown),
            x if x == MachineAction::Discover as i32 => Ok(MachineAction::Discover),
            x if x == MachineAction::Adopt as i32 => Ok(MachineAction::Adopt),
            x if x == MachineAction::Test as i32 => Ok(MachineAction::Test),
            x if x == MachineAction::Commission as i32 => Ok(MachineAction::Commission),
            x if x == MachineAction::Assign as i32 => Ok(MachineAction::Assign),
            x if x == MachineAction::Fail as i32 => Ok(MachineAction::Fail),
            x if x == MachineAction::Decommission as i32 => Ok(MachineAction::Decommission),
            x if x == MachineAction::Recommission as i32 => Ok(MachineAction::Recommission),
            x if x == MachineAction::Unassign as i32 => Ok(MachineAction::Unassign),
            x if x == MachineAction::Release as i32 => Ok(MachineAction::Release),
            x if x == MachineAction::Cleanup as i32 => Ok(MachineAction::Cleanup),
            _ => Err(()),
        }
    }
}

impl Serialize for MachineEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("MachineEvent", 4)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field("machine_id", &self.machine_id)?;
        state.serialize_field("event", &self.event)?;
        state.serialize_field("time", &self.time.as_ref().map(|ts| ts.seconds))?;

        state.end()
    }
}

impl Serialize for MachineList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("MachineList", 1)?;

        state.serialize_field("machines", &self.machines)?;

        state.end()
    }
}

impl Serialize for Machine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Machine", 7)?;

        state.serialize_field("id", &self.id)?;
        //state.serialize_field("supported_instance_type", &self.supported_instance_type)?;
        state.serialize_field("created", &self.created.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("updated", &self.updated.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("deployed", &self.deployed.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("events", &self.events)?;
        state.serialize_field("interfaces", &self.interfaces)?;

        state.end()
    }
}

impl Serialize for Instance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Instance", 10)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field("segment_id", &self.segment_id)?;
        state.serialize_field("machine_id", &self.machine_id)?;
        state.serialize_field("user_data", &self.user_data)?;
        state.serialize_field("custome_ipxe", &self.custom_ipxe)?;
        state.serialize_field("ssh_keys", &self.ssh_keys)?;

        state.serialize_field("requested", &self.requested.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("started", &self.started.as_ref().map(|ts| ts.seconds))?;
        state.serialize_field("finished", &self.finished.as_ref().map(|ts| ts.seconds))?;

        state.serialize_field("interfaces", &self.interfaces)?;

        state.end()
    }
}

impl Serialize for InstanceList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("InstanceList", 1)?;

        state.serialize_field("instances", &self.instances)?;

        state.end()
    }
}

impl Serialize for InstanceSubnet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("InstanceSubnet", 6)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field("machine_interface_id", &self.machine_interface_id)?;
        state.serialize_field("network_segment_id", &self.network_segment_id)?;
        state.serialize_field("instance_id", &self.instance_id)?;
        state.serialize_field("vfid", &self.vfid)?;
        state.serialize_field("addresses", &self.addresses)?;

        state.end()
    }
}

impl Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Domain", 5)?;

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
