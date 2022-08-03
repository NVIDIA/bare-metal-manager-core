//use std::str::FromStr;

pub use address_selection_strategy::AddressSelectionStrategy;
pub use auth::SshKeyValidationRequest;
pub use dhcp_record::DhcpRecord;
pub use domain::{Domain, NewDomain};
pub use instance::{Instance, NewInstance};
pub use instance_subnet::InstanceSubnet;
pub use instance_subnet_address::InstanceSubnetAddress;
pub use instance_subnet_event::InstanceSubnetEvent;
pub use instance_type::{
    DeactivateInstanceType, InstanceType, NewInstanceType, UpdateInstanceType,
};
pub use ipmi::{BmcMetaData, BmcMetaDataRequest, BmcMetadataItem, UserRoles};
pub use machine::Machine;
pub use machine_action::MachineAction;
pub use machine_event::MachineEvent;
pub use machine_interface::MachineInterface;
pub use machine_interface_address::MachineInterfaceAddress;
pub use machine_state::MachineState;
pub use machine_topology::MachineTopology;
pub use network_prefix::{NetworkPrefix, NewNetworkPrefix};
pub use network_prefix_event::NetworkPrefixEvent;
pub use network_segment::{IpAllocationResult, NetworkSegment, NewNetworkSegment};
pub use resource_record::{DnsQuestion, DnsResponse, Dnsrr, ResourceRecord};
pub use tags::{Tag, TagAssociation, TagCreate, TagDelete, TagTargetKind, TagsList};
pub use vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc};
pub use vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};
pub use vpc_resource_state::VpcResourceState;

pub mod migrations;

mod address_selection_strategy;
mod auth;
mod dhcp_record;
mod domain;
mod instance;
mod instance_subnet;
mod instance_subnet_address;
mod instance_subnet_event;
mod instance_type;
mod ipmi;
mod machine;
mod machine_action;
mod machine_event;
mod machine_interface;
mod machine_interface_address;
mod machine_state;
mod machine_topology;
mod network_prefix;
mod network_prefix_event;
mod network_segment;
mod resource_record;
mod tags;
mod vpc;
mod vpc_resource_action;
mod vpc_resource_leaf;
mod vpc_resource_leaf_event;
pub mod vpc_resource_state;

///
/// A parameter to find() to filter machines by Uuid;
///
pub enum UuidKeyedObjectFilter<'a> {
    /// Don't filter by uuid
    All,

    /// Filter by a list of uuids
    List(&'a [uuid::Uuid]),

    /// Retrieve a single machine
    One(uuid::Uuid),
}
