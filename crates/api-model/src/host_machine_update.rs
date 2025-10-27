use forge_uuid::machine::MachineId;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct HostMachineUpdate {
    pub id: MachineId,
}
