mod configuration_resource_pool;
mod leaf;
mod managed_resource;
mod resource_group;

pub use configuration_resource_pool::{
    ConfigurationResourcePoolRanges, ConfigurationResourcePoolSpec, ConfigurationResourcePoolStatus,
};

pub use leaf::{LeafControl, LeafSpec, LeafStatus, LeafStatusConditions};

pub use managed_resource::{
    ManagedResourceSpec, ManagedResourceStatus, ManagedResourceStatusConditions,
    ManagedResourceStatusHostAccessIPs, ManagedResourceStatusNetworkFabricReference,
};

pub use resource_group::{
    ResourceGroupNetwork, ResourceGroupSpec, ResourceGroupStatus, ResourceGroupStatusConditions,
    ResourceGroupStatusNetwork, ResourceGroupStatusSoftwareNetworkConfiguration,
};
