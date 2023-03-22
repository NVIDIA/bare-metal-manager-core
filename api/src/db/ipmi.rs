/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use ::rpc::forge as rpc;
use forge_credentials::{CredentialKey, CredentialProvider, Credentials};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction};

use super::{machine::DbMachineId, DatabaseError};
use crate::model::machine::machine_id::{try_parse_machine_id, MachineId};
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "user_roles")]
#[sqlx(rename_all = "lowercase")]
pub enum UserRoles {
    User,
    Administrator,
    Operator,
    Noaccess,
}

impl Display for UserRoles {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            UserRoles::User => "user",
            UserRoles::Administrator => "administrator",
            UserRoles::Operator => "operator",
            UserRoles::Noaccess => "noaccess",
        };

        write!(f, "{}", string)
    }
}

#[derive(Debug, Clone)]
pub struct BmcMetaDataGetRequest {
    pub machine_id: MachineId,
    pub role: UserRoles,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct MachineHostInformation {
    address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcMetadataItem {
    pub username: String,
    pub password: String,
    pub role: UserRoles,
}

pub struct BmcMetaDataUpdateRequest {
    pub machine_id: MachineId,
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

impl TryFrom<rpc::BmcMetaDataGetRequest> for BmcMetaDataGetRequest {
    type Error = CarbideError;

    fn try_from(value: rpc::BmcMetaDataGetRequest) -> Result<Self, Self::Error> {
        let machine_id = value
            .machine_id
            .ok_or_else(|| CarbideError::GenericError("Machine id is null".to_string()))?;
        Ok(BmcMetaDataGetRequest {
            machine_id: try_parse_machine_id(&machine_id)?,
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

impl BmcMetaDataGetRequest {
    pub async fn get_bmc_meta_data<C>(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        credential_provider: &C,
    ) -> CarbideResult<rpc::BmcMetaDataGetResponse>
    where
        C: CredentialProvider + ?Sized,
    {
        let address = self.get_bmc_host_ip(txn).await?;

        let credentials = credential_provider
            .get_credentials(CredentialKey::Bmc {
                machine_id: self.machine_id.to_string(),
                user_role: self.role.to_string(),
            })
            .await
            .map_err(|err| {
                CarbideError::GenericError(format!("Error getting credentials for BMC: {:?}", err))
            })?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        Ok(rpc::BmcMetaDataGetResponse {
            ip: address,
            user: username,
            password,
        })
    }

    pub async fn get_bmc_host_ip(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<String, DatabaseError> {
        let query = r#"SELECT machine_topologies.topology->>'ipmi_ip' as address
            FROM machine_topologies WHERE machine_id=$1"#;
        sqlx::query_as::<_, MachineHostInformation>(query)
            .bind(self.machine_id.to_string())
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
            .map(|machine_host_information| machine_host_information.address)
    }
}

impl TryFrom<rpc::BmcMetaDataUpdateRequest> for BmcMetaDataUpdateRequest {
    type Error = CarbideError;
    fn try_from(request: rpc::BmcMetaDataUpdateRequest) -> CarbideResult<Self> {
        let mut data: Vec<BmcMetadataItem> = Vec::new();
        for v in request.data {
            let role = UserRoles::from(rpc::UserRoles::from_i32(v.role).ok_or_else(|| {
                CarbideError::GenericError(format!("Can't convert role: {:?}", v.role))
            })?);
            data.push(BmcMetadataItem {
                username: v.user.clone(),
                password: v.password.clone(),
                role,
            });
        }

        Ok(BmcMetaDataUpdateRequest {
            machine_id: match request.machine_id {
                Some(id) => try_parse_machine_id(&id)?,
                _ => {
                    return Err(CarbideError::GenericError("Machine id is null".to_string()));
                }
            },
            ip: request.ip.clone(),
            data,
        })
    }
}

impl BmcMetaDataUpdateRequest {
    async fn insert_into_credentials_store(
        &self,
        credential_provider: &impl CredentialProvider,
    ) -> CarbideResult<()> {
        for data in self.data.iter() {
            credential_provider
                .set_credentials(
                    CredentialKey::Bmc {
                        machine_id: self.machine_id.to_string(),
                        user_role: data.role.to_string(),
                    },
                    Credentials::UsernamePassword {
                        username: data.username.clone(),
                        password: data.password.clone(),
                    },
                )
                .await
                .map_err(|err| {
                    CarbideError::GenericError(format!(
                        "Error setting credential for BMC: {:?}",
                        err
                    ))
                })?;
        }

        Ok(())
    }

    async fn update_ipmi_ip_into_topologies(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        // A entry with same machine id is already created by discover_machine call.
        // Just update json by adding a ipmi_ip entry.
        let query = "
UPDATE machine_topologies
SET topology = jsonb_set(topology, '{ipmi_ip}', $1, true)
WHERE machine_id=$2
RETURNING machine_id";

        let _: Option<(DbMachineId,)> = sqlx::query_as(query)
            .bind(&json!(self.ip))
            .bind(self.machine_id.to_string())
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn update_bmc_meta_data(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        credential_provider: &impl CredentialProvider,
    ) -> CarbideResult<rpc::BmcMetaDataUpdateResponse> {
        self.update_ipmi_ip_into_topologies(txn).await?;
        self.insert_into_credentials_store(credential_provider)
            .await?;
        Ok(rpc::BmcMetaDataUpdateResponse {})
    }
}
