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

pub fn grpcurl(addr: SocketAddr, endpoint: &str, data: &str) -> eyre::Result<String> {
    // We don't pass the full path to grpcurl here and rely on the fact
    // that `Command` searches the PATH. This makes function signatures tidier.
    let out = process::Command::new("grpcurl")
        .arg("-d")
        .arg(data)
        .arg("-insecure")
        .arg("-max-time")
        .arg("5")
        .arg(addr.to_string())
        .arg(format!("forge.Forge/{endpoint}"))
        .output()?;
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
    let response = grpcurl(addr, endpoint, data)?;
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
