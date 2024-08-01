/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ops::DerefMut;

use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{db::DatabaseError, CarbideError, CarbideResult};
use prost_types::value::Kind;
use prost_types::Value;
use serde::{Deserialize, Serialize};
use serde_json::Number as JsonNumber;
use serde_json::Value as JsonValue;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct MachineValidationExternalConfig {
    pub name: String,
    pub description: String,
    pub config: serde_json::Value,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationExternalConfig {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config: sqlx::types::Json<serde_json::Value> = row.try_get("config")?;

        Ok(MachineValidationExternalConfig {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            config: config.0,
        })
    }
}
pub fn to_struct(json: serde_json::Map<String, serde_json::Value>) -> ::prost_types::Struct {
    ::prost_types::Struct {
        fields: json
            .into_iter()
            .map(|(k, v)| (k, serde_json_to_prost(v)))
            .collect(),
    }
}
fn serde_json_to_prost(json: serde_json::Value) -> ::prost_types::Value {
    use ::prost_types::value::Kind::*;
    use serde_json::Value::*;
    ::prost_types::Value {
        kind: Some(match json {
            Null => NullValue(0 /* wat? */),
            Bool(v) => BoolValue(v),
            Number(n) => NumberValue(n.as_f64().expect("Non-f64-representable number")),
            String(s) => StringValue(s),
            Array(v) => ListValue(::prost_types::ListValue {
                values: v.into_iter().map(serde_json_to_prost).collect(),
            }),
            Object(v) => StructValue(to_struct(v)),
        }),
    }
}
impl From<MachineValidationExternalConfig> for rpc::forge::MachineValidationExternalConfig {
    fn from(value: MachineValidationExternalConfig) -> Self {
        rpc::forge::MachineValidationExternalConfig {
            name: value.name,
            config: Some(serde_json_to_prost(value.config)),
            description: Some(value.description),
        }
    }
}
fn prost_value_to_serde(value: &Value) -> JsonValue {
    let Some(kind) = value.clone().kind else {
        return JsonValue::Null;
    };
    match kind {
        Kind::NullValue(_) => JsonValue::Null,
        Kind::NumberValue(v) => JsonValue::Number(JsonNumber::from_f64(v).unwrap()),
        Kind::StringValue(v) => JsonValue::String(v.clone()),
        Kind::BoolValue(v) => JsonValue::Bool(v),
        Kind::StructValue(v) => {
            let map: serde_json::Map<String, JsonValue> = v
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), prost_value_to_serde(v)))
                .collect();
            JsonValue::Object(map)
        }
        Kind::ListValue(v) => {
            let vec: Vec<JsonValue> = v.values.iter().map(prost_value_to_serde).collect();
            JsonValue::Array(vec)
        }
    }
}

impl TryFrom<rpc::forge::MachineValidationExternalConfig> for MachineValidationExternalConfig {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineValidationExternalConfig) -> CarbideResult<Self> {
        Ok(MachineValidationExternalConfig {
            name: value.name,
            description: "".to_string(),
            config: prost_value_to_serde(&value.config.unwrap()),
        })
    }
}

impl MachineValidationExternalConfig {
    pub async fn find_config_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> CarbideResult<Self> {
        let query = "SELECT * FROM machine_validation_external_config WHERE name=$1";
        sqlx::query_as::<_, Self>(query)
            .bind(name)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn save(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        description: &str,
        config: serde_json::Value,
    ) -> CarbideResult<()> {
        let query =
            "INSERT INTO machine_validation_external_config (name, description, config) VALUES ($1, $2, $3) RETURNING name";

        sqlx::query_as(query)
            .bind(name)
            .bind(description)
            .bind(sqlx::types::Json(&config))
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }

    async fn update(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        config: serde_json::Value,
    ) -> CarbideResult<()> {
        let query =
            "UPDATE machine_validation_external_config SET config=$2 WHERE name=$1 RETURNING name";

        sqlx::query_as(query)
            .bind(name)
            .bind(sqlx::types::Json(&config))
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }

    pub async fn create_or_update(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        description: &str,
        data: Option<::prost_types::Value>,
    ) -> CarbideResult<()> {
        let Some(config) = data else {
            return Err(CarbideError::MissingArgument("Config is missing"));
        };
        let json = prost_value_to_serde(&config);
        let _ = match Self::save(txn, name, description, json.clone()).await {
            Ok(_) => return Ok(()),
            Err(_) => Self::update(txn, name, json).await,
        };
        Ok(())
    }
}
#[cfg(test)]
mod test {}
