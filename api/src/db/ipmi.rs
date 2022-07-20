use crate::{CarbideError, CarbideResult};
use rpc::forge::v0 as rpc;
use sqlx::{Postgres, Transaction};
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "user_roles")]
#[sqlx(rename_all = "lowercase")]
pub enum UserRoles {
    User,
    Administrator,
    Operator,
    Noaccess,
}

#[derive(Debug, Clone)]
pub struct BmcMetaDataRequest {
    pub machine_id: Uuid,
    pub role: UserRoles,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct MachineConsoleMetadata {
    address: String,
    username: String,
    password: String,
}

impl From<rpc::UserRoles> for UserRoles {
    fn from(action: rpc::UserRoles) -> Self {
        match action {
            rpc::UserRoles::User => UserRoles::User,
            rpc::UserRoles::Administrator => UserRoles::Administrator,
            rpc::UserRoles::Operator => UserRoles::Operator,
            rpc::UserRoles::Noaccess => UserRoles::Noaccess,
        }
    }
}

impl From<UserRoles> for rpc::UserRoles {
    fn from(action: UserRoles) -> Self {
        match action {
            UserRoles::User => rpc::UserRoles::User,
            UserRoles::Administrator => rpc::UserRoles::Administrator,
            UserRoles::Operator => rpc::UserRoles::Operator,
            UserRoles::Noaccess => rpc::UserRoles::Noaccess,
        }
    }
}

impl FromStr for UserRoles {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "user" => Ok(UserRoles::User),
            "administrator" => Ok(UserRoles::Administrator),
            "operator" => Ok(UserRoles::Operator),
            "noaccess" => Ok(UserRoles::Noaccess),
            x => Err(CarbideError::GenericError(format!(
                "Unknown role found: {}",
                x
            ))),
        }
    }
}

impl TryFrom<rpc::BmcMetaDataRequest> for BmcMetaDataRequest {
    type Error = CarbideError;

    fn try_from(value: rpc::BmcMetaDataRequest) -> Result<Self, Self::Error> {
        let uuid = value
            .machine_id
            .ok_or_else(|| CarbideError::GenericError("Machine id is null".to_string()))?;
        Ok(BmcMetaDataRequest {
            machine_id: Uuid::try_from(uuid)?,
            role: UserRoles::from(match rpc::UserRoles::from_i32(value.role) {
                Some(x) => x,
                None => {
                    return Err(CarbideError::GenericError(
                        "Invalid role found.".to_string(),
                    ))
                }
            }),
        })
    }
}

impl BmcMetaDataRequest {
    pub async fn get_bmc_meta_data(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::BmcMetaDataResponse> {
        let query = r#"SELECT machine_topologies.topology->>'ipmi_ip' as address, 
            machine_console_metadata.username as username, machine_console_metadata.password as password 
            FROM machine_topologies 
            INNER JOIN machine_console_metadata 
                ON machine_console_metadata.machine_id=machine_topologies.machine_id
            WHERE machine_console_metadata.role=$1 
                AND machine_topologies.machine_id=$2"#;
        let host = sqlx::query_as::<_, MachineConsoleMetadata>(query)
            .bind(&self.role)
            .bind(&self.machine_id)
            .fetch_one(txn)
            .await
            .map_err(CarbideError::from)?;

        // Return first response with same role.
        Ok(rpc::BmcMetaDataResponse {
            ip: host.address,
            user: host.username,
            password: host.password,
        })
    }
}
