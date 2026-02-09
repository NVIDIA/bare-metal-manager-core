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

use std::net::SocketAddr;

use eyre::ContextCompat;
use rand::prelude::IndexedRandom;
use serde::{Deserialize, Serialize};
use tokio::process;

use crate::utils::LOCALHOST_CERTS;

pub async fn grpcurl<T: ToString>(
    addrs: &[SocketAddr],
    endpoint: &str,
    data: Option<T>,
) -> eyre::Result<String> {
    grpcurl_for(addrs, endpoint, data, None).await
}

pub async fn grpcurl_for<T: ToString>(
    addrs: &[SocketAddr],
    endpoint: &str,
    data: Option<T>,
    for_ip: Option<&str>,
) -> eyre::Result<String> {
    let address = addrs
        .choose(&mut rand::rng())
        .context("No API servers configured")?
        .to_string();
    let grpc_endpoint = format!("forge.Forge/{endpoint}");
    let mut args = vec![
        "-cacert",
        LOCALHOST_CERTS.ca_cert.to_str().unwrap(),
        "-cert",
        LOCALHOST_CERTS.client_cert.to_str().unwrap(),
        "-key",
        LOCALHOST_CERTS.client_key.to_str().unwrap(),
        "-emit-defaults",
        "-max-time",
        "60",
        &address,
        &grpc_endpoint,
    ];
    let header;
    if let Some(for_ip) = for_ip {
        args.insert(0, "-H");
        header = format!("x-forwarded-for: {for_ip}");
        args.insert(1, &header);
    }
    let post_data;
    if let Some(d) = data {
        post_data = d.to_string();
        args.insert(0, "-d");
        args.insert(1, &post_data);
    }

    // We don't pass the full path to grpcurl here and rely on the fact
    // that `Command` searches the PATH. This makes function signatures tidier.
    let out = process::Command::new("grpcurl").args(args).output().await?;
    let response = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        tracing::error!("grpcurl {endpoint} STDOUT: {response}");
        tracing::error!(
            "grpcurl {endpoint} STDERR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("grpcurl {endpoint} exit status code {}", out.status);
    }
    Ok(response.to_string())
}

// grpcurl then extra id from response and return that
pub async fn grpcurl_id(addrs: &[SocketAddr], endpoint: &str, data: &str) -> eyre::Result<String> {
    let response = grpcurl(addrs, endpoint, Some(data)).await?;
    tracing::info!("grpcurl respose: {response}");
    let resp: IdValue = serde_json::from_str(&response)?;
    Ok(resp.id.value)
}

#[derive(Serialize, Deserialize)]
pub struct IdValue {
    pub id: Value,
}

#[derive(Serialize, Deserialize)]
pub struct Value {
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Id {
    pub id: String,
}
