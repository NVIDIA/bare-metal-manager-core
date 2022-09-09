use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ConfigurationResourcePoolSpec defines the desired state of ConfigurationResourcePool
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "networkfabric.vpc.forge.gitlab-master.nvidia.com",
    version = "v1alpha1",
    kind = "ConfigurationResourcePool",
    plural = "configurationresourcepools"
)]
#[kube(namespaced)]
#[kube(status = "ConfigurationResourcePoolStatus")]
pub struct ConfigurationResourcePoolSpec {
    /// AllocationBlockBitSize is allocation block size in bits.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "allocationBlockSize"
    )]
    pub allocation_block_size: Option<i32>,
    /// Range is the ConfigurationResourcePool half-open range [Start, End).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<ConfigurationResourcePoolRanges>>,
    /// Type specifies the PoolRange type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// PoolRange specify a continuous range.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ConfigurationResourcePoolRanges {
    /// End is end of the PoolRange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// Start is start of the PoolRange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
}

/// ConfigurationResourcePoolStatus defines the observed state of ConfigurationResourcePool
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ConfigurationResourcePoolStatus {}
