/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::model::ConfigValidationError;
use std::collections::HashMap;

use ::rpc::errors::RpcDataConversionError;

/// Metadata that can get associated with Forge managed resources
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// user-defined resource name
    pub name: String,
    /// optional user-defined resource description
    pub description: String,
    /// optional user-defined key/ value pairs
    pub labels: HashMap<String, String>,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            name: "default_name".to_string(),
            description: String::new(),
            labels: HashMap::new(),
        }
    }
}

impl TryFrom<Metadata> for rpc::Metadata {
    type Error = RpcDataConversionError;

    fn try_from(metadata: Metadata) -> Result<Self, Self::Error> {
        Ok(rpc::Metadata {
            name: metadata.name,
            description: metadata.description,
            labels: metadata
                .labels
                .iter()
                .map(|(key, value)| rpc::forge::Label {
                    key: key.clone(),
                    value: if value.is_empty() {
                        None
                    } else {
                        Some(value.clone())
                    },
                })
                .collect(),
        })
    }
}

impl TryFrom<rpc::Metadata> for Metadata {
    type Error = RpcDataConversionError;

    fn try_from(metadata: rpc::Metadata) -> Result<Self, Self::Error> {
        let mut labels = std::collections::HashMap::new();

        for label in metadata.labels {
            let key = label.key.clone();
            let value = label.value.clone().unwrap_or_default();

            if labels.contains_key(&key) {
                return Err(RpcDataConversionError::InvalidLabel(format!(
                    "Duplicate key found: {}",
                    key
                )));
            }

            labels.insert(key, value);
        }

        Ok(Metadata {
            name: metadata.name,
            description: metadata.description,
            labels,
        })
    }
}

impl Metadata {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.name.len() <= 1 || self.name.len() > 256 {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Name must be between 2 and 256 characters long, got {} characters",
                self.name.len()
            )));
        }

        if !self.name.is_ascii() {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Name '{}' must contain ASCII characters only",
                self.name
            )));
        }

        for (key, value) in &self.labels {
            if !key.is_ascii() {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label key '{key}' must contain ASCII characters only"
                )));
            }

            if key.len() > 255 {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label key '{key}' is too long (max 255 characters)"
                )));
            }
            if key.is_empty() {
                return Err(ConfigValidationError::InvalidValue(
                    "Label key cannot be empty.".to_string(),
                ));
            }
            if value.len() > 255 {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label value '{value}' is too long (max 255 characters)"
                )));
            }
        }

        if self.labels.len() > 10 {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Cannot have more than 10 labels, got {}",
                self.labels.len()
            )));
        }

        Ok(())
    }
}
