/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use nico_rpc::errors::RpcDataConversionError;
use nico_rpc::forge;
use nico_uuid::machine::MachineInterfaceId;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

///
/// A custom boot response is a representation of custom data for booting machines, either with pxe or user-data
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

impl TryFrom<forge::MachineBootOverride> for MachineBootOverride {
    type Error = RpcDataConversionError;
    fn try_from(value: forge::MachineBootOverride) -> Result<Self, Self::Error> {
        let machine_interface_id =
            value
                .machine_interface_id
                .ok_or(RpcDataConversionError::MissingArgument(
                    "machine_interface_id",
                ))?;
        Ok(MachineBootOverride {
            machine_interface_id,
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        })
    }
}

impl From<MachineBootOverride> for forge::MachineBootOverride {
    fn from(value: MachineBootOverride) -> Self {
        forge::MachineBootOverride {
            machine_interface_id: Some(value.machine_interface_id),
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        }
    }
}
