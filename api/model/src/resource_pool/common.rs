use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::resource_pool::{ResourcePool, ResourcePoolStats};

/// DPU VPC loopback IP pool
/// Must match a pool defined in dev/resource_pools.toml
pub const LOOPBACK_IP: &str = "lo-ip";
/// VNI pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VNI: &str = "vni";
/// vlan-id pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VLANID: &str = "vlan-id";
/// vpc-vni pool: L3VNI for the whole VPC
/// Must match a pool defined in dev/resource_pools.toml
pub const VPC_VNI: &str = "vpc-vni";
/// DPU Specific ASN for use with FNN
/// Must match a pool defined in dev/resource_pools.toml
pub const FNN_ASN: &str = "fnn-asn";
/// VPC DPU loopback IP, used as in FNN.
/// Must match a pool defined in dev/resource_pools.toml
pub const VPC_DPU_LOOPBACK: &str = "vpc-dpu-lo";
pub const DPA_VNI: &str = "dpa-vni";

/// Returns the name of the resource pool used for a certain IB fabric
pub fn ib_pkey_pool_name(fabric: &str) -> String {
    format!("ib_fabrics.{fabric}.pkey")
}

/// ResourcePools that are used throughout the application
#[derive(Debug)]
pub struct CommonPools {
    pub ethernet: EthernetPools,
    pub infiniband: IbPools,
    pub dpa: DpaPools,
    pub pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>>,
    /// Instructs the metric task to stop.
    /// We rely on `CommonPools` being dropped to instruct the metric task to stop
    pub _stop_sender: oneshot::Sender<()>,
}

#[derive(Debug)]
pub struct DpaPools {
    pub pool_dpa_vni: Arc<ResourcePool<i32>>,
}

/// ResourcePools that are used for ethernet virtualization
#[derive(Debug)]
pub struct EthernetPools {
    pub pool_loopback_ip: Arc<ResourcePool<Ipv4Addr>>,
    pub pool_vlan_id: Arc<ResourcePool<i16>>,
    pub pool_vni: Arc<ResourcePool<i32>>,
    pub pool_vpc_vni: Arc<ResourcePool<i32>>,
    pub pool_fnn_asn: Arc<ResourcePool<u32>>,
    pub pool_vpc_dpu_loopback_ip: Arc<ResourcePool<Ipv4Addr>>,
}

/// ResourcePools that are used for infiniband
#[derive(Clone, Debug, Default)]
pub struct IbPools {
    pub pkey_pools: Arc<HashMap<String, ResourcePool<u16>>>,
}
