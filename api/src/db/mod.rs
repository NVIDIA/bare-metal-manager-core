pub mod address_selection_strategy;
pub mod auth;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod domain;
pub mod dpu_machine;
pub mod instance;
pub mod instance_subnet;
pub mod instance_subnet_address;
pub mod instance_subnet_event;
pub mod instance_type;
pub mod ipmi;
pub mod machine;
pub mod machine_action;
pub mod machine_event;
pub mod machine_interface;
pub mod machine_interface_address;
pub mod machine_state;
pub mod machine_topology;
pub mod migrations;
pub mod network_prefix;
pub mod network_prefix_event;
pub mod network_segment;
pub mod resource_record;
pub mod tags;
pub mod vpc;
pub mod vpc_resource_action;
pub mod vpc_resource_leaf;
pub mod vpc_resource_leaf_event;
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
