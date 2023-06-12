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

use std::io::{BufRead, BufReader};
use std::path;
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

// What to look for in logs toknow the server has started
const START_TOKEN: &str = "Start carbide-api";

pub struct CarbideApi(Arc<Mutex<CarbideApiInner>>);

struct CarbideApiInner {
    pub has_started: bool,
    process: process::Child,
}

pub fn start(
    root_dir: &path::Path,
    db_url: &str,
    vault_token: &str,
) -> Result<CarbideApi, eyre::Report> {
    let carbide_api = root_dir.join("target/debug/carbide-api");
    let tls_cert = root_dir.join("dev/certs/server_identity.pem");
    let tls_key = root_dir.join("dev/certs/server_identity.key");

    let mut process = process::Command::new(carbide_api)
        .env("VAULT_ADDR", "http://127.0.0.1:8200")
        .env("VAULT_MOUNT_LOCATION", "secret")
        .env("VAULT_TOKEN", vault_token)
        .arg("run")
        .arg("--listen=127.0.0.1:1079")
        .arg(format!("--identity-pemfile-path={}", tls_cert.display()))
        .arg(format!("--identity-keyfile-path={}", tls_key.display()))
        .arg(format!("--datastore={db_url}"))
        .arg("--auth-permissive-mode")
        .arg("--manage-vpc")
        .arg("--asn=65535")
        .arg("--rapid-iterations")
        .arg(format!(
            "--casbin-policy-file={}",
            root_dir.join("api/casbin-policy.csv").display()
        ))
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()?;
    let stdout = BufReader::new(process.stdout.take().unwrap());
    let stderr = BufReader::new(process.stderr.take().unwrap());

    let api = Arc::new(Mutex::new(CarbideApiInner {
        has_started: false,
        process,
    }));

    let api_stdout = api.clone();
    thread::spawn(move || {
        let mut maybe_api = Some(api_stdout);
        for line in stdout.lines().map(|l| l.unwrap()) {
            if line.contains(START_TOKEN) {
                maybe_api.unwrap().lock().unwrap().has_started = true;
                maybe_api = None; // drop it so we can reclaim the Arc later
            }
            tracing::debug!("{}", line);
        }
    });
    thread::spawn(move || {
        for line in stderr.lines() {
            tracing::error!("{}", line.unwrap());
        }
    });

    Ok(CarbideApi(api))
}

impl CarbideApi {
    pub fn has_started(&self) -> bool {
        self.0.lock().unwrap().has_started
    }
}

impl Drop for CarbideApi {
    fn drop(&mut self) {
        let inner = self.0.lock().unwrap();
        let mut kill = process::Command::new("kill")
            .args(["-s", "TERM", &inner.process.id().to_string()])
            .spawn()
            .expect("'kill' carbide-api");
        kill.wait().expect("wait");
    }
}
