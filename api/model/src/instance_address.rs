use forge_uuid::instance::InstanceId;
use forge_uuid::network::NetworkSegmentId;
use sqlx::FromRow;

#[derive(Debug, FromRow, Clone)]
pub struct InstanceAddress {
    pub instance_id: InstanceId,
    pub segment_id: NetworkSegmentId,
    // pub id: Uuid,          // unused
    pub address: std::net::IpAddr,
    // pub prefix: IpNetwork, // unused
}
