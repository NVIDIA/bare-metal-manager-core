use crate::errors::{CarbideError, CarbideResult};
use forge_uuid::machine::MachineInterfaceId;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

///
/// A custom boot response is a representation of custom data for booting machines, either with pxe or user-data
///
#[derive(Debug, sqlx::Encode)]
pub struct MachineBootOverride {
    pub machine_interface_id: MachineInterfaceId,
    pub custom_pxe: Option<String>,
    pub custom_user_data: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for MachineBootOverride {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineBootOverride {
            machine_interface_id: row.try_get("machine_interface_id")?,
            custom_pxe: row.try_get("custom_pxe")?,
            custom_user_data: row.try_get("custom_user_data")?,
        })
    }
}

impl TryFrom<rpc::forge::MachineBootOverride> for MachineBootOverride {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineBootOverride) -> CarbideResult<Self> {
        let machine_interface_id = value
            .machine_interface_id
            .ok_or_else(|| CarbideError::MissingArgument("machine_interface_id"))?;
        Ok(MachineBootOverride {
            machine_interface_id,
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        })
    }
}

impl From<MachineBootOverride> for rpc::forge::MachineBootOverride {
    fn from(value: MachineBootOverride) -> Self {
        rpc::forge::MachineBootOverride {
            machine_interface_id: Some(value.machine_interface_id),
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        }
    }
}
