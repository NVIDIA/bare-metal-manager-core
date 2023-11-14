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

use std::{net::SocketAddr, process};

use serde::{Deserialize, Serialize};

pub fn grpcurl<T: ToString>(
    addr: SocketAddr,
    endpoint: &str,
    data: Option<T>,
) -> eyre::Result<String> {
    let address = addr.to_string();
    let grpc_endpoint = format!("forge.Forge/{endpoint}");
    let mut args = vec![
        "-insecure",
        "-emit-defaults",
        "-max-time",
        "5",
        &address,
        &grpc_endpoint,
    ];
    let post_data;
    if let Some(d) = data {
        post_data = d.to_string();
        args.insert(0, "-d");
        args.insert(1, &post_data);
    }
    // We don't pass the full path to grpcurl here and rely on the fact
    // that `Command` searches the PATH. This makes function signatures tidier.
    let out = process::Command::new("grpcurl").args(args).output()?;
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
pub fn grpcurl_id(addr: SocketAddr, endpoint: &str, data: &str) -> eyre::Result<String> {
    let response = grpcurl(addr, endpoint, Some(data))?;
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
