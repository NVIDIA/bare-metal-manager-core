use forge_uuid::instance::InstanceId;
use model::instance::config::network::{
    InstanceInterfaceConfig, InstanceNetworkConfig, InterfaceFunctionId,
};
use model::machine::Machine;
use model::network_segment::NetworkSegmentType;
use sqlx::PgConnection;

use crate::db;
use crate::errors::CarbideResult;
/// Allocate IP's for this network config, filling the InstanceInterfaceConfigs with the newly
/// allocated IP's.
pub async fn with_allocated_ips(
    value: InstanceNetworkConfig,
    txn: &mut PgConnection,
    instance_id: InstanceId,
    machine: &Machine,
) -> CarbideResult<InstanceNetworkConfig> {
    db::instance_address::allocate(txn, instance_id, value, machine).await
}

/// Find any host_inband segments on the given machine, and replicate them into this instance
/// network config. This is because allocation requests do not need to explicitly enumerate
/// a host's in-band (non-dpu) network segments: they cannot be configured through carbide.
pub async fn with_inband_interfaces_from_machine(
    mut value: InstanceNetworkConfig,
    txn: &mut PgConnection,
    machine_id: &::forge_uuid::machine::MachineId,
) -> CarbideResult<InstanceNetworkConfig> {
    let host_inband_segment_ids = db::network_segment::find_ids_by_machine_id(
        txn,
        machine_id,
        Some(NetworkSegmentType::HostInband),
    )
    .await?;

    for host_inband_segment_id in host_inband_segment_ids {
        // Only add it to the instance config if there isn't already an interface in this segment
        if !value
            .interfaces
            .iter()
            .any(|i| i.network_segment_id == Some(host_inband_segment_id))
        {
            value.interfaces.push(InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: Some(host_inband_segment_id),
                network_details: None,
                ip_addrs: Default::default(),
                interface_prefixes: Default::default(),
                network_segment_gateways: Default::default(),
                host_inband_mac_address: None,
                device_locator: None,
                internal_uuid: uuid::Uuid::new_v4(),
            })
        }
    }

    Ok(value)
}
