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

use std::collections::HashMap;
use std::fmt::Display;

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client::ForgeClientConfig;

use crate::common::{AppState, Machine, MachineInterface};
use crate::routes::RpcContext;

pub enum PxeErrorCode {
    ArchitectureNotFound = 105,
    InterfaceNotFound = 106,
    InstructionsEmpty = 107,
}

fn generate_error_template<D1, D2>(error_str: D1, error_code: D2) -> HashMap<String, String>
where
    D1: Display,
    D2: Display,
{
    HashMap::from([(
        "error".to_string(),
        format!(
            r#"
echo {error_str} ||
exit {error_code} ||
"#,
        ),
    )])
}

pub async fn whoami(machine: Machine, state: State<AppState>) -> impl IntoResponse {
    let (template_key, template_data) =
        if let Some(instructions) = machine.instructions.discovery_instructions {
            match (instructions.machine_interface, instructions.domain) {
                (Some(interface), Some(_)) => {
                    let mut template_data = HashMap::new();
                    template_data.insert("fqdn".to_string(), interface.hostname);
                    template_data.insert("mac_address".to_string(), interface.mac_address);

                    ("whoami".to_string(), template_data)
                }
                _ => (
                    "error".to_string(),
                    generate_error_template(
                        "Could not load interface or domain",
                        PxeErrorCode::InterfaceNotFound as isize,
                    ),
                ),
            }
        } else {
            (
                "error".to_string(),
                generate_error_template(
                    "Could not load instructions",
                    PxeErrorCode::InstructionsEmpty as isize,
                ),
            )
        };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

pub async fn boot(contents: MachineInterface, state: State<AppState>) -> impl IntoResponse {
    let machine_interface_id = contents.interface_id;

    let (template_key, template_data) = match contents.architecture {
        Some(arch) => {
            let mut template_data = HashMap::new();
            template_data.insert("interface_id".to_string(), machine_interface_id.to_string());
            template_data.insert("pxe_url".to_string(), state.runtime_config.pxe_url.clone());

            if !state.runtime_config.static_pxe_url.is_empty() {
                template_data.insert(
                    "static_pxe_url".to_string(),
                    state.runtime_config.static_pxe_url.clone(),
                );
            }

            let instructions = RpcContext::get_pxe_instructions(
                arch.into(),
                machine_interface_id,
                contents.product,
                &state.runtime_config.internal_api_url,
                &ForgeClientConfig::new(
                    state.runtime_config.forge_root_ca_path.clone(),
                    Some(ClientCert {
                        cert_path: state.runtime_config.server_cert_path.clone(),
                        key_path: state.runtime_config.server_key_path.clone(),
                    }),
                ),
            )
            .await
            .unwrap_or_else(|err| {
                eprintln!("{err}");
                format!(
                    r#"
echo Failed to fetch custom_ipxe: {err} ||
exit 101 ||
"#
                )
            })
            .replace("[api_url]", &state.runtime_config.client_facing_api_url);

            template_data.insert("ipxe".to_string(), instructions);

            ("pxe", template_data)
        }
        None => (
            "error",
            generate_error_template(
                "Architecture not found".to_string(),
                PxeErrorCode::ArchitectureNotFound as isize,
            ),
        ),
    };

    axum_template::Render(template_key, state.engine.clone(), template_data)
}

pub fn get_router(path_prefix: &str) -> Router<AppState> {
    Router::new()
        .route(
            format!("{}/{}", path_prefix, "whoami").as_str(),
            get(whoami),
        )
        .route(format!("{}/{}", path_prefix, "boot").as_str(), get(boot))
}
