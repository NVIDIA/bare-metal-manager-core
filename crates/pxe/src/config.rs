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
use std::env;

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub internal_api_url: String,
    pub client_facing_api_url: String,
    pub pxe_url: String,
    pub static_pxe_url: String,
    pub forge_root_ca_path: String,
    pub server_cert_path: String,
    pub server_key_path: String,
    pub bind_address: String,
    pub bind_port: u16,
    pub template_directory: String,
}

impl RuntimeConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        let carbide_pxe_url =
            env::var("CARBIDE_PXE_URL").unwrap_or_else(|_| "http://carbide-pxe.forge".to_string());
        let this = Self {
            internal_api_url: env::var("CARBIDE_API_INTERNAL_URL").unwrap_or_else(|_| {
                "https://carbide-api.forge-system.svc.cluster.local:1079".to_string()
            }),
            client_facing_api_url: env::var("CARBIDE_API_URL")
                .unwrap_or_else(|_| "https://carbide-api.forge".to_string()),
            pxe_url: carbide_pxe_url.clone(),
            static_pxe_url: env::var("CARBIDE_STATIC_PXE_URL").unwrap_or(carbide_pxe_url),
            forge_root_ca_path: env::var("FORGE_ROOT_CAFILE_PATH").map_err(|_| {
                "Could not extract FORGE_ROOT_CAFILE_PATH from environment".to_string()
            })?,
            server_cert_path: env::var("FORGE_CLIENT_CERT_PATH").map_err(|_| {
                "Could not extract FORGE_CLIENT_CERT_PATH from environment".to_string()
            })?,
            server_key_path: env::var("FORGE_CLIENT_KEY_PATH").map_err(|_| {
                "Could not extract FORGE_CLIENT_KEY_PATH from environment".to_string()
            })?,
            bind_address: env::var("PXE_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string()),
            bind_port: env::var("PXE_BIND_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .map_err(|_| "not a parsable bind port for runtime config?".to_string())?,
            template_directory: env::var("CARBIDE_PXE_TEMPLATE_DIRECTORY")
                .unwrap_or_else(|_| "/opt/carbide/pxe/templates".to_string()),
        };

        Ok(this)
    }
}
