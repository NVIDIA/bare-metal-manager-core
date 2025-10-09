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
use std::net::SocketAddr;
use std::process::Stdio;

use eyre::Context;
use tokio::io::AsyncBufReadExt;
use tokio::process;
use tokio::sync::oneshot;

const ROOT_TOKEN: &str = "Root Token";

#[derive(Debug)]
pub struct Vault {
    pub process: process::Child,
    pub token: String,
}

pub async fn start(addr: SocketAddr) -> Result<Vault, eyre::Report> {
    let bins = crate::utils::find_prerequisites()?;

    let mut process =
        tokio::process::Command::new(bins.get("vault").expect("vault command not found in PATH"))
            .arg("server")
            .arg("-dev")
            .arg(format!("-dev-listen-address={addr}"))
            .env_remove("VAULT_ADDR")
            .env_remove("VAULT_CLIENT_KEY")
            .env_remove("VAULT_CLIENT_CERT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

    let stdout = tokio::io::BufReader::new(process.stdout.take().unwrap());
    let stderr = tokio::io::BufReader::new(process.stderr.take().unwrap());

    let (token_tx, token_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut lines = stdout.lines();
        let mut sender = Some(token_tx);
        while let Some(line) = lines.next_line().await? {
            let mut parts = line.trim().split(':');
            if let Some(left) = parts.next()
                && left == ROOT_TOKEN
                && let Some(sender) = sender.take()
            {
                sender.send(parts.next().unwrap().to_string()).ok();
            }
            // there's no logger so can't use tracing
            println!("{line}");
        }
        Ok::<(), eyre::Error>(())
    });

    tokio::spawn(async move {
        let mut lines = stderr.lines();
        while let Some(line) = lines.next_line().await? {
            // there's no logger so can't use tracing
            eprintln!("{line}");
        }
        Ok::<(), eyre::Error>(())
    });

    // Vault dev prints the token immediately on startup, so block and wait for it
    let token = token_rx.await.context("waiting for vault token")?;
    Ok(Vault { process, token })
}
