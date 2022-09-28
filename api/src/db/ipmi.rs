use std::convert::TryFrom;
use std::str::FromStr;

use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use ::rpc::forge as rpc;

use crate::{CarbideError, CarbideResult};

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
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

#[derive(Debug, Clone)]
pub struct BmcMetadataItem {
    pub username: String,
    pub password: String,
    pub role: UserRoles,
}

pub struct BmcMetaData {
    pub machine_id: Uuid,
    pub ip: String,
    pub data: Vec<BmcMetadataItem>,
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
                    ));
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

impl TryFrom<rpc::BmcMetaData> for BmcMetaData {
    type Error = CarbideError;
    fn try_from(value: rpc::BmcMetaData) -> CarbideResult<Self> {
        let mut data: Vec<BmcMetadataItem> = Vec::new();
        for v in value.data {
            let role = UserRoles::from(rpc::UserRoles::from_i32(v.role).ok_or_else(|| {
                CarbideError::GenericError(format!("Can't convert role: {:?}", v.role))
            })?);
            data.push(BmcMetadataItem {
                username: v.user.clone(),
                password: v.password.clone(),
                role,
            });
        }

        Ok(BmcMetaData {
            machine_id: match value.machine_id {
                Some(x) => match uuid::Uuid::try_from(x) {
                    Ok(uuid) => uuid,
                    Err(err) => {
                        return Err(CarbideError::GenericError(err.to_string()));
                    }
                },
                _ => {
                    return Err(CarbideError::GenericError("Machine id is null".to_string()));
                }
            },
            ip: value.ip.clone(),
            data,
        })
    }
}

impl BmcMetaData {
    async fn insert_into_bmc_metadata(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = r#"INSERT INTO machine_console_metadata as mt(machine_id, username, role, password)
                       VALUES ($1, $2, $3, $4)
                       ON CONFLICT ON CONSTRAINT machine_console_metadata_machine_id_username_role_key
                       DO UPDATE
                            SET username=$2, role=$3, password=$4
                            WHERE mt.machine_id=$1
                       RETURNING mt.machine_id"#;

        for data in &self.data {
            let _: (Uuid,) = sqlx::query_as(query)
                .bind(&self.machine_id)
                .bind(&data.username)
                .bind(&data.role)
                .bind(&data.password)
                .fetch_one(&mut *txn)
                .await
                .map_err(CarbideError::from)?;
        }
        Ok(())
    }

    async fn update_ipmi_ip_into_topologies(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        // A entry with same machine id is already created by discover_machine call.
        // Just update json by adding a ipmi_ip entry.
        let query = r#"UPDATE machine_topologies 
                       SET topology = jsonb_set(topology, '{ipmi_ip}', $1, true) 
                       WHERE machine_id=$2
                       RETURNING machine_id"#;

        let _: Option<(Uuid,)> = sqlx::query_as(query)
            .bind(&json!(self.ip))
            .bind(&self.machine_id)
            .fetch_optional(&mut *txn)
            .await
            .map_err(CarbideError::from)?;
        Ok(())
    }

    pub async fn update_bmc_meta_data(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::BmcStatus> {
        self.update_ipmi_ip_into_topologies(txn).await?;
        self.insert_into_bmc_metadata(txn).await?;
        Ok(rpc::BmcStatus {})
    }
}
