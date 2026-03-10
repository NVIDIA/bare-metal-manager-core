// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentManagerConfig {
    #[serde(default = "default_nsm_backend")]
    pub nv_switch_backend: String,
    #[serde(default = "default_psm_backend")]
    pub power_shelf_backend: String,
    #[serde(default)]
    pub nsm: Option<BackendEndpointConfig>,
    #[serde(default)]
    pub psm: Option<BackendEndpointConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendEndpointConfig {
    pub url: String,
}

fn default_nsm_backend() -> String {
    "nsm".into()
}

fn default_psm_backend() -> String {
    "psm".into()
}

impl Default for ComponentManagerConfig {
    fn default() -> Self {
        Self {
            nv_switch_backend: default_nsm_backend(),
            power_shelf_backend: default_psm_backend(),
            nsm: None,
            psm: None,
        }
    }
}
