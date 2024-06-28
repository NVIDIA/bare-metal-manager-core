/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use ::rpc::forge as rpc;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction};

use super::{machine::DbMachineId, DatabaseError};
use crate::model::bmc_info::BmcInfo;
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

#[derive(Debug, Clone)]
pub struct BmcMetaDataGetRequest {
    pub machine_id: MachineId,
}

impl TryFrom<rpc::BmcMetaDataGetRequest> for BmcMetaDataGetRequest {
    type Error = CarbideError;

    fn try_from(value: rpc::BmcMetaDataGetRequest) -> Result<Self, Self::Error> {
        let machine_id = value
            .machine_id
            .ok_or_else(|| CarbideError::GenericError("Machine id is null".to_string()))?;
        Ok(BmcMetaDataGetRequest {
            machine_id: try_parse_machine_id(&machine_id)?,
        })
    }
}

impl BmcMetaDataGetRequest {
    async fn get_bmc_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credential_provider: &dyn CredentialProvider,
    ) -> CarbideResult<(String, String)> {
        let credentials = credential_provider
            .get_credentials(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
            })
            .await
            .map_err(|err| {
                CarbideError::GenericError(format!("Error getting credentials for BMC: {:?}", err))
            })?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        Ok((username, password))
    }

    pub async fn get_bmc_meta_data(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        credential_provider: &dyn CredentialProvider,
    ) -> CarbideResult<rpc::BmcMetaDataGetResponse> {
        let bmc_info = self.get_bmc_information(txn).await?;
        let bmc_mac_str = bmc_info.mac.ok_or(CarbideError::GenericError(format!(
            "BMC Info in machine_topologies does not have a MAC address for machine {}",
            self.machine_id
        )))?;
        let bmc_mac_address = bmc_mac_str
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;
        let (username, password) = self
            .get_bmc_credentials(bmc_mac_address, credential_provider)
            .await?;

        Ok(rpc::BmcMetaDataGetResponse {
            ip: bmc_info.ip.unwrap_or_default(),
            port: bmc_info.port.map(|p| p as u32),
            mac: bmc_mac_str,
            user: username,
            password,
        })
    }

    pub async fn get_bmc_information(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<BmcInfo, DatabaseError> {
        let query = r#"SELECT machine_topologies.topology->>'bmc_info' as bmc_info FROM machine_topologies WHERE machine_id=$1"#;
        let bmc_info = sqlx::query_as::<_, BmcInfo>(query)
            .bind(self.machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(bmc_info)
    }
}

pub struct BmcMetaDataUpdateRequest {
    pub machine_id: MachineId,
    pub bmc_info: BmcInfo,
}

impl TryFrom<rpc::BmcMetaDataUpdateRequest> for BmcMetaDataUpdateRequest {
    type Error = CarbideError;
    fn try_from(request: rpc::BmcMetaDataUpdateRequest) -> CarbideResult<Self> {
        Ok(BmcMetaDataUpdateRequest {
            machine_id: match request.machine_id {
                Some(id) => try_parse_machine_id(&id)?,
                _ => {
                    return Err(CarbideError::GenericError("Machine id is null".to_string()));
                }
            },
            bmc_info: request.bmc_info.unwrap_or_default().into(),
        })
    }
}

impl BmcMetaDataUpdateRequest {
    pub async fn update_bmc_network_into_topologies(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        // A entry with same machine id is already created by discover_machine call.
        // Just update json by adding a ipmi_ip entry.
        let query = "UPDATE machine_topologies SET topology = jsonb_set(topology, '{bmc_info}', $1, true) WHERE machine_id=$2 RETURNING machine_id";
        let bmc_info: BmcInfo = self.bmc_info.clone();
        tracing::info!("put bmc_info: {:?}", bmc_info);

        let _: Option<(DbMachineId,)> = sqlx::query_as(query)
            .bind(&json!(bmc_info))
            .bind(self.machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn update_bmc_meta_data(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::BmcMetaDataUpdateResponse> {
        self.update_bmc_network_into_topologies(txn).await?;
        Ok(rpc::BmcMetaDataUpdateResponse {})
    }
}
