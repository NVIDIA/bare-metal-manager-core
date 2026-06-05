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

use carbide_uuid::spx::SpxPartitionId;
use serde::{Deserialize, Serialize};

use crate::ConfigValidationError;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSpxConfig {
    /// Configures how SpectrumX NICs are set up
    pub spx_attachments: Vec<InstanceSpxAttachment>,
}

impl InstanceSpxConfig {
    /// Validates the spx configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        Ok(())
    }

    pub fn verify_update_allowed_to(
        &self,
        _new_config: &Self,
    ) -> Result<(), ConfigValidationError> {
        Ok(())
    }

    pub fn is_spx_config_update_requested(&self, new_config: &Self) -> bool {
        self != new_config
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpxAttachmentType {
    Physical = 0,
    Virtual = 1,
    Ovn = 2,
}

impl TryFrom<i32> for SpxAttachmentType {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SpxAttachmentType::Physical),
            1 => Ok(SpxAttachmentType::Virtual),
            2 => Ok(SpxAttachmentType::Ovn),
            _ => Err("Invalid SpxAttachmentType value"),
        }
    }
}

/// The configuration that a customer desires for an instances SpectrumX NICs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSpxAttachment {
    pub device: String,
    pub device_instance: u32,
    pub mac_address: Option<String>,
    pub spx_partition_id: SpxPartitionId,
    pub attachment_type: SpxAttachmentType,
    pub virtual_function_id: Option<u32>,
}
