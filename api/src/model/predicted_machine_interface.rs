use crate::model::network_segment::NetworkSegmentType;
use forge_uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct PredictedMachineInterface {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}

#[derive(Debug, Clone)]
pub struct NewPredictedMachineInterface<'a> {
    pub machine_id: &'a MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}
