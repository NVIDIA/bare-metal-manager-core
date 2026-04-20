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
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use eyre::Context;
use tokio::io::AsyncBufReadExt;
use tokio::process;
use tokio::sync::oneshot;

const ROOT_TOKEN: &str = "Root Token";
const VAULT_CACERT_ENV_STRING: &str = "$ export VAULT_CACERT";

#[derive(Debug)]
pub struct Vault {
    pub process: process::Child,
    pub token: String,
    pub ca_cert: String,
}

pub async fn start(addr: SocketAddr) -> Result<Vault, eyre::Report> {
    let bins = crate::utils::find_prerequisites()?;

    let mut process =
        tokio::process::Command::new(bins.get("vault").expect("vault command not found in PATH"))
            .arg("server")
            .arg("-dev-tls")
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
    let (ca_tx, ca_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut lines = stdout.lines();
        let mut token_sender = Some(token_tx);
        let mut ca_sender = Some(ca_tx);
        while let Some(line) = lines.next_line().await? {
            let mut token_parts = line.trim().split(':');
            let mut ca_parts = line.trim().split('=');
            if let Some(left) = ca_parts.next()
                && left == VAULT_CACERT_ENV_STRING
                && let Some(ca_sender) = ca_sender.take()
            {
                // Vault prints: $ export VAULT_CACERT='/path/to/cert'
                // Strip the surrounding single quotes that the shell export syntax includes.
                let raw = ca_parts.next().unwrap();
                let path = raw.trim_matches('\'').to_string();
                ca_sender.send(path).ok();
            }
            if let Some(left) = token_parts.next()
                && left == ROOT_TOKEN
                && let Some(token_sender) = token_sender.take()
            {
                token_sender
                    .send(token_parts.next().unwrap().to_string())
                    .ok();
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
    let ca_cert = ca_rx.await.context("waiting for vault CA cert")?;

    // Vault announces the cert path in its stdout log before it finishes writing the
    // file to disk. Poll until the file is present so callers can use it immediately.
    let cert_ready_deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if Path::new(&ca_cert).exists() {
            break;
        }
        if std::time::Instant::now() >= cert_ready_deadline {
            eyre::bail!("Vault CA cert never appeared at {ca_cert} after 10 seconds");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Ok(Vault {
        process,
        token,
        ca_cert,
    })
}
