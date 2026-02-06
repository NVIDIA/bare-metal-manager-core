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

// src/registry.rs
// This defines code for the MlxVariableRegistry, which has a name,
// defines the variables that are a part of this registry, as well
// as any device filters, as in devices which are allowed to use
// this registry.

use ::rpc::errors::RpcDataConversionError;
use ::rpc::protos::mlx_device::MlxVariableRegistry as MlxVariableRegistryPb;
use mlxconfig_device::filters::{DeviceFilter, DeviceFilterSet};
use serde::{Deserialize, Serialize};

use crate::variable::MlxConfigVariable;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlxVariableRegistry {
    pub name: String,
    pub variables: Vec<MlxConfigVariable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<DeviceFilterSet>,
}

impl MlxVariableRegistry {
    // new creates a new empty registry with the given name.
    pub fn new<N: Into<String>>(name: N) -> Self {
        Self {
            name: name.into(),
            variables: Vec::new(),
            filters: None,
        }
    }

    // name sets the registry name (builder pattern).
    pub fn name<N: Into<String>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    // variables sets the variables list (builder pattern).
    pub fn variables(mut self, variables: Vec<MlxConfigVariable>) -> Self {
        self.variables = variables;
        self
    }

    // add_variable adds a single variable to the registry (builder pattern).
    pub fn add_variable(mut self, variable: MlxConfigVariable) -> Self {
        self.variables.push(variable);
        self
    }

    // with_filters sets the device filter set (builder pattern).
    pub fn with_filters(mut self, filters: DeviceFilterSet) -> Self {
        self.filters = Some(filters);
        self
    }

    // with_filter adds a single device filter to the registry (builder pattern).
    // If no filter set exists, creates a new one. If one exists, adds to it.
    pub fn with_filter(mut self, filter: DeviceFilter) -> Self {
        match self.filters {
            Some(ref mut filter_set) => {
                filter_set.add_filter(filter);
            }
            None => {
                let mut filter_set = DeviceFilterSet::new();
                filter_set.add_filter(filter);
                self.filters = Some(filter_set);
            }
        }
        self
    }

    // get_variable returns a variable from the registry,
    // or None if it's not in there.
    pub fn get_variable(&self, name: &str) -> Option<&MlxConfigVariable> {
        self.variables.iter().find(|v| v.name == name)
    }

    // variable_names returns all the variable
    // names defined in the registry.
    pub fn variable_names(&self) -> Vec<&str> {
        self.variables.iter().map(|v| v.name.as_str()).collect()
    }

    // has_filters returns whether this registry has device filters configured.
    pub fn has_filters(&self) -> bool {
        self.filters.as_ref().is_some_and(|f| f.has_filters())
    }

    // filter_summary returns a summary of configured device filters for logging.
    pub fn filter_summary(&self) -> String {
        match &self.filters {
            Some(filters) => filters.to_string(),
            None => "No filters".to_string(),
        }
    }

    // matches_device checks if a device matches this registry's filters.
    // Returns true if no filters are configured (allows all devices).
    pub fn matches_device(&self, device_info: &mlxconfig_device::info::MlxDeviceInfo) -> bool {
        self.filters
            .as_ref()
            .is_none_or(|filter_set| filter_set.matches(device_info))
    }
}

impl From<MlxVariableRegistry> for MlxVariableRegistryPb {
    fn from(registry: MlxVariableRegistry) -> Self {
        let variables: Vec<_> = registry.variables.into_iter().map(|v| v.into()).collect();

        MlxVariableRegistryPb {
            name: registry.name,
            filters: registry.filters.map(|f| f.into()),
            variables,
        }
    }
}

impl TryFrom<MlxVariableRegistryPb> for MlxVariableRegistry {
    type Error = RpcDataConversionError;

    fn try_from(pb: MlxVariableRegistryPb) -> Result<Self, Self::Error> {
        let variables: Result<Vec<_>, _> = pb.variables.into_iter().map(|v| v.try_into()).collect();

        let filters: Option<Result<DeviceFilterSet, _>> = pb.filters.map(|f| f.try_into());

        let filters = match filters {
            Some(Ok(f)) => Some(f),
            Some(Err(e)) => {
                return Err(RpcDataConversionError::InvalidArgument(format!(
                    "failed to convert filters: {e}"
                )));
            }
            None => None,
        };

        Ok(MlxVariableRegistry {
            name: pb.name,
            variables: variables?,
            filters,
        })
    }
}
