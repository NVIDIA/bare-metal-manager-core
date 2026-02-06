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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::config::Config;

#[derive(Clone)]
pub struct PdnsSocket {
    pub socket: Arc<Mutex<UnixListener>>,
}
impl PdnsSocket {
    pub fn new_socket(socket_config: Arc<Config>) -> Result<Self, eyre::Report> {
        let socket_path_str = socket_config.socket_path.display();

        // Ensure the socket is removed before binding if it exists
        if Path::new(socket_config.socket_path.as_path()).exists() {
            if let Err(e) = fs::remove_file(&socket_config.socket_path) {
                tracing::error!(
                    path = %socket_config.socket_path.display(),
                    error = %e,
                    error_kind = ?e.kind(),
                    "Failed to remove stale socket file"
                );
            } else {
                tracing::info!(
                    path = %socket_path_str,
                    "Removed stale socket file"
                );
            }
        } else {
            tracing::debug!(
                path = %socket_path_str,
                "Socket file does not exist"
            );
        }

        tracing::info!(
            path = %socket_config.socket_path.display(),
            permissions = %format!("{:o}", socket_config.socket_permissions),
            carbide_uri = %socket_config.carbide_uri,
            "Creating new socket"
        );

        // Set permissions on the socket file
        let socket = UnixListener::bind(socket_config.socket_path.as_path()).map_err(|e| {
            tracing::error!(
                path = %socket_config.socket_path.display(),
                error = %e,
                error_kind = ?e.kind(),
                "Failed to bind to UNIX socket"
            );
            eyre::eyre!("Failed to bind to UNIX socket: {}", e)
        })?;
        tracing::info!(
            path = %socket_path_str,
            "Bound to UNIX socket"
        );

        let octal_permissions =
            u32::from_str_radix(&socket_config.socket_permissions.to_string(), 8).map_err(|e| {
                tracing::error!(
                    permissions = %socket_config.socket_permissions,
                    error = %e,
                    "Failed to parse socket permissions"
                );
                eyre::eyre!("Failed to parse socket permissions: {}", e)
            })?;

        fs::set_permissions(
            &socket_config.socket_path,
            fs::Permissions::from_mode(octal_permissions),
        )
        .map_err(|e| {
            tracing::error!(
                path = %socket_config.socket_path.display(),
                permissions = %format!("{:o}", octal_permissions),
                error = %e,
                error_kind = ?e.kind(),
                "Failed to set socket permissions"
            );
            eyre::eyre!("Failed to set socket permissions: {}", e)
        })?;

        let metadata = fs::metadata(&socket_config.socket_path).map_err(|e| {
            tracing::error!(
                path = %socket_config.socket_path.display(),
                error = %e,
                error_kind = ?e.kind(),
                "Failed to read socket metadata"
            );
            e
        })?;
        let mode = metadata.permissions().mode();
        tracing::info!(
            path = %socket_config.socket_path.display(),
            permissions_octal = %format!("{:o}", mode),
            "Socket permissions set successfully"
        );

        let socket = Arc::new(Mutex::new(socket));
        Ok(PdnsSocket { socket })
    }
}
