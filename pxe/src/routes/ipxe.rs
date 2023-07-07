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
use std::collections::HashMap;
use std::fmt::Display;

use rocket::{get, routes, Route};
use rocket_dyn_templates::Template;

use rpc::forge_tls_client::{ForgeClientCert, ForgeTlsConfig};

use crate::routes::RpcContext;
use crate::{Machine, MachineInterface, RuntimeConfig};

#[derive(serde::Serialize)]
pub struct IpxeScript<'a> {
    pub content: &'a str,
}

#[get("/whoami")]
pub async fn whoami(machine: Machine) -> Template {
    Template::render("whoami", machine)
}

fn generate_error_template<D1, D2>(error_str: D1, error_code: D2) -> Template
where
    D1: Display,
    D2: Display,
{
    let err = format!(
        r#"
echo {error_str} ||
exit {error_code} ||
"#,
    );
    let mut context = HashMap::new();
    context.insert("error".to_string(), err);
    Template::render("error", &context)
}

pub enum PxeErrorCode {
    ArchitectureNotFound = 105,
}

#[get("/boot")]
pub async fn boot(contents: MachineInterface, config: RuntimeConfig) -> Result<Template, Template> {
    let machine_interface_id = contents.interface_id;
    let arch = contents.architecture.ok_or_else(|| {
        generate_error_template(
            "Architecture not found".to_string(),
            PxeErrorCode::ArchitectureNotFound as isize,
        )
    })?;

    let mut context = HashMap::new();
    context.insert("interface_id".to_string(), machine_interface_id.to_string());
    context.insert("pxe_url".to_string(), config.pxe_url.clone());

    let forge_tls_config = ForgeTlsConfig {
        root_ca_path: config.forge_root_ca_path.clone(),
        client_cert: Some(ForgeClientCert {
            cert_path: config.server_cert_path.clone(),
            key_path: config.server_key_path.clone(),
        }),
    };
    let instructions = RpcContext::get_pxe_instructions(
        arch,
        machine_interface_id,
        config.internal_api_url.clone(),
        forge_tls_config,
    )
    .await
    .unwrap_or_else(|err| {
        eprintln!("{}", err);
        format!(
            r#"
echo Failed to fetch custome_ipxe: {} ||
exit 101 ||
"#,
            err
        )
    })
    .replace("[api_url]", &config.client_facing_api_url);

    context.insert("ipxe".to_string(), instructions);

    Ok(Template::render("pxe", &context))
}

pub fn routes() -> Vec<Route> {
    routes![boot, whoami]
}
