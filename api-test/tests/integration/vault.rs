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

use std::io;
use std::io::BufRead;
use std::path;
use std::process;
use std::sync::mpsc;
use std::thread;

const ROOT_TOKEN: &str = "Root Token";

pub struct Vault {
    process: process::Child,
    token: String,
}

impl Vault {
    pub fn token(&self) -> &str {
        &self.token
    }
}

pub fn start(vault_bin: &path::Path) -> Result<Vault, eyre::Report> {
    let mut process = process::Command::new(vault_bin)
        .arg("server")
        .arg("-dev")
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()?;

    let stdout = io::BufReader::new(process.stdout.take().unwrap());
    let stderr = io::BufReader::new(process.stderr.take().unwrap());

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in stdout.lines() {
            let line = line.unwrap();
            let mut parts = line.trim().split(':');
            if let Some(left) = parts.next() {
                if left == ROOT_TOKEN {
                    let _ = sender.send(parts.next().unwrap().to_string());
                }
            }
            // there's no logger so can't use tracing
            println!("{}", line);
        }
    });
    thread::spawn(move || {
        for line in stderr.lines() {
            // there's no logger so can't use tracing
            eprintln!("{}", line.unwrap());
        }
    });

    // Vault dev prints the token immediately on startup, so block and wait for it
    let token = receiver.recv()?;
    Ok(Vault { process, token })
}

impl Drop for Vault {
    fn drop(&mut self) {
        stop_vault(&self.process.id().to_string());
    }
}

fn stop_vault(pid: &str) {
    let mut kill = process::Command::new("kill")
        .args(["-s", "TERM", pid])
        .spawn()
        .expect("'kill' vault");
    kill.wait().expect("wait");
}
