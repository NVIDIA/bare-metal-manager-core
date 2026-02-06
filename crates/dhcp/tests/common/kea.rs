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
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

pub struct Kea {
    temp_conf_file: PathBuf,

    dhcp_in_port: u16,
    dhcp_out_port: u16,

    // Hold this around so that when Kea is dropped, TempDir is dropped and cleaned up
    temp_base_directory: TempDir,

    process: Option<Child>,
}

impl Kea {
    // Start the Kea DHCP server as a sub-process and return a handle to it
    // Stops when the returned object is dropped.
    pub fn new(
        api_server_url: &str,
        dhcp_in_port: u16,
        dhcp_out_port: u16,
    ) -> Result<Kea, eyre::Report> {
        let temp_base_directory = tempfile::tempdir()?;

        let temp_conf_file = temp_base_directory.path().join("kea-dhcp4.conf");

        let mut temp_conf_fd = File::create(&temp_conf_file)?;
        temp_conf_fd.write_all(Kea::config(api_server_url).as_bytes())?;

        // Close the file so it's updated for Kea.
        drop(temp_conf_fd);

        Ok(Kea {
            temp_conf_file,
            temp_base_directory,
            dhcp_in_port,
            dhcp_out_port,
            process: None,
        })
    }

    pub fn run(&mut self) -> Result<(), eyre::Report> {
        let mut process = Command::new("/usr/sbin/kea-dhcp4")
            .env("KEA_PIDFILE_DIR", self.temp_base_directory.path())
            .env("KEA_LOCKFILE_DIR", self.temp_base_directory.path())
            .arg("-c")
            .arg(self.temp_conf_file.as_os_str())
            .arg("-p")
            .arg(self.dhcp_in_port.to_string())
            .arg("-P")
            .arg(self.dhcp_out_port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = BufReader::new(process.stdout.take().unwrap());
        let stderr = BufReader::new(process.stderr.take().unwrap());
        thread::spawn(move || {
            for line in stdout.lines() {
                println!("KEA STDOUT: {}", line.unwrap());
            }
        });
        thread::spawn(move || {
            for line in stderr.lines() {
                println!("KEA STDOUT: {}", line.unwrap());
            }
        });
        thread::sleep(Duration::from_millis(500)); // let Kea start

        self.process = Some(process);

        Ok(())
    }

    fn config(api_server_url: &str) -> String {
        let hook_lib_d = format!(
            "{}/../../target/debug/libdhcp.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let hook_lib_r = format!(
            "{}/../../target/release/libdhcp.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let hook_lib = if Path::new(&hook_lib_r).exists() {
            hook_lib_r
        } else if Path::new(&hook_lib_d).exists() {
            hook_lib_d
        } else {
            // If `cargo build` has not been run yet (after a `cargo clean`), the `build.rs` script won't have
            // generated libdhcp.so. So we do it ourselves.
            println!("Could not find Kea hooks dynamic library at '{hook_lib_d}'. Building.");
            test_cdylib::build_current_project();
            hook_lib_d
        };

        let conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": [ "lo" ],
                "dhcp-socket-type": "udp"
            },
            "lease-database": {
                "type": "memfile",
                "persist": false,
                "lfc-interval": 3600
            },
            "multi-threading": {
                "enable-multi-threading": true,
                "thread-pool-size": 4,
                "packet-queue-size": 28,
                "user-context": {
                    "comment": "Values above are Kea recommendations for memfile backend",
                    "url": "https://kea.readthedocs.io/en/kea-2.2.0/arm/dhcp4-srv.html#multi-threading-settings-with-different-database-backends"
                }
            },
            "renew-timer": 900,
            "rebind-timer": 1800,
            "valid-lifetime": 3600,
            "hooks-libraries": [
                {
                    "library": hook_lib,
                    "parameters": {
                        "carbide-api-url": api_server_url,
                        "carbide-metrics-endpoint": "[::]:1089",
                        "carbide-nameservers": "1.1.1.1,8.8.8.8",
                        "carbide-provisioning-server-ipv4": "127.0.0.1"
                    }
                }
            ],
            "subnet4": [
                {
                    "subnet": "0.0.0.0/0",
                    "pools": [{
                        "pool": "0.0.0.0-255.255.255.255"
                    }]
                }
            ],
            "user-context": {
                "comment": "Change severity below to DEBUG and run 'cargo test -- --nocapture' for verbose test output",
            },
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output_options": [{"output": "stdout"}],
                    "severity": "WARN",
                    "debuglevel": 99
                },
                {
                    "name": "kea-dhcp4.carbide-rust",
                    "output_options": [{"output": "stdout"}],
                    "severity": "WARN",
                    "debuglevel": 10
                },
                {
                    "name": "kea-dhcp4.carbide-callouts",
                    "output_options": [{"output": "stdout"}],
                    "severity": "FATAL",
                    "debuglevel": 10
                }
            ]
        }
        });
        conf.to_string()
    }
}

impl Drop for Kea {
    fn drop(&mut self) {
        if let Some(process) = &mut self.process {
            // Rust stdlib can only send a KILL (9) to sub-process. Thankfully dhcp already depends on
            // libc so we can use that.
            unsafe {
                libc::kill(process.id() as i32, libc::SIGTERM);
            }
            thread::sleep(Duration::from_millis(100));
            if let Ok(None) = process.try_wait() {
                process.kill().unwrap(); // -9
            }
        }
    }
}
