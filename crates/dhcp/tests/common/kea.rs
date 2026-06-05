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
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use tempfile::TempDir;

/// One row from kea's memfile CSV (kea-leases4.csv). Only the fields the
/// lease4 hook tests care about are exposed.
//
// dead_code is allowed because not every test binary that includes `common`
// inspects the lease file -- the existing booturl/multithreaded tests only
// look at packets.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LeaseEntry {
    pub address: Ipv4Addr,
    pub hwaddr: String,
    /// 0 = default (active). Other states (declined, expired-reclaimed)
    /// shouldn't appear in our tests but are exposed for completeness.
    pub state: u32,
}

pub struct Kea {
    temp_conf_file: PathBuf,
    #[allow(dead_code)] // only read by tests that inspect the memfile
    lease_file: PathBuf,

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
        let lease_file = temp_base_directory.path().join("kea-leases4.csv");

        let mut temp_conf_fd = File::create(&temp_conf_file)?;
        temp_conf_fd.write_all(Kea::config(api_server_url, &lease_file).as_bytes())?;

        // Close the file so it's updated for Kea.
        drop(temp_conf_fd);

        Ok(Kea {
            temp_conf_file,
            lease_file,
            temp_base_directory,
            dhcp_in_port,
            dhcp_out_port,
            process: None,
        })
    }

    /// Path to the persistent lease file Kea writes (memfile backend with persist=true).
    /// Used by tests to assert on what got persisted.
    #[allow(dead_code)]
    pub fn lease_file_path(&self) -> &Path {
        &self.lease_file
    }

    /// Read kea-leases4.csv and return all entries. Skips the header row.
    /// Returns an empty Vec if the file doesn't exist yet (Kea writes it
    /// lazily on first lease event).
    #[allow(dead_code)]
    pub fn read_leases(&self) -> Vec<LeaseEntry> {
        let Ok(file) = File::open(&self.lease_file) else {
            return Vec::new();
        };
        let mut entries = Vec::new();
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let Ok(line) = line else { continue };
            // Header is "address,hwaddr,client_id,...,state,user_context,pool_id"
            if i == 0 || line.is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() < 10 {
                continue;
            }
            let Ok(address) = cols[0].parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(state) = cols[9].parse::<u32>() else {
                continue;
            };
            entries.push(LeaseEntry {
                address,
                hwaddr: cols[1].to_string(),
                state,
            });
        }
        entries
    }

    /// Convenience: find the active lease entry for a given MAC string
    /// (kea writes MAC as colon-separated lowercase hex, e.g. "02:00:00:00:00:01").
    #[allow(dead_code)]
    pub fn find_lease(&self, hwaddr: &str) -> Option<LeaseEntry> {
        self.read_leases()
            .into_iter()
            .find(|l| l.hwaddr == hwaddr && l.state == 0)
    }

    /// Poll the lease file for an entry matching `hwaddr` whose address is
    /// `expected`, up to `timeout`. Returns true if found, false if the
    /// deadline passes. Useful because Kea's persist-to-disk can lag the
    /// gRPC ACK by a few ms.
    #[allow(dead_code)]
    pub fn wait_for_lease(&self, hwaddr: &str, expected: Ipv4Addr, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(lease) = self.find_lease(hwaddr)
                && lease.address == expected
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
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

        // Poll until Kea binds its DHCP receive port, so the test doesn't race.
        // Trying to bind the same port ourselves: success means Kea hasn't taken it yet;
        // AddrInUse means Kea is listening and we're ready to proceed.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            thread::sleep(Duration::from_millis(100));
            match UdpSocket::bind(format!("0.0.0.0:{}", self.dhcp_in_port)) {
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => break,
                Ok(_) => {}
                Err(e) => return Err(eyre::eyre!("Unexpected error probing Kea readiness: {e}")),
            }
            if Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "Kea did not bind DHCP port {} within 15 seconds",
                    self.dhcp_in_port
                ));
            }
        }

        self.process = Some(process);

        Ok(())
    }

    fn config(api_server_url: &str, lease_file: &Path) -> String {
        // Locate libdhcp.so. Cargo may put it under either `target/debug/`
        // (default) or `target/...something.../debug/` (when CARGO_BUILD_TARGET
        // is set in the env). Check release before debug so a `--release`
        // test build wins.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let candidates: Vec<String> = {
            let target_triple = std::env::var("CARGO_BUILD_TARGET").ok();
            let triple_subdir = target_triple
                .as_deref()
                .map(|t| format!("{t}/"))
                .unwrap_or_default();
            // NOTE: cargo only updates the non-deps `libdhcp.so` on the first
            // build after a clean; subsequent rebuilds touch `deps/libdhcp.so`
            // only. Prefer the deps copy so we always pick up fresh rebuilds.
            vec![
                format!("{manifest_dir}/../../target/{triple_subdir}release/deps/libdhcp.so"),
                format!("{manifest_dir}/../../target/release/deps/libdhcp.so"),
                format!("{manifest_dir}/../../target/{triple_subdir}debug/deps/libdhcp.so"),
                format!("{manifest_dir}/../../target/debug/deps/libdhcp.so"),
                format!("{manifest_dir}/../../target/{triple_subdir}release/libdhcp.so"),
                format!("{manifest_dir}/../../target/release/libdhcp.so"),
                format!("{manifest_dir}/../../target/{triple_subdir}debug/libdhcp.so"),
                format!("{manifest_dir}/../../target/debug/libdhcp.so"),
            ]
        };
        let hook_lib = match candidates.iter().find(|p| Path::new(p).exists()) {
            Some(p) => p.clone(),
            None => {
                // If `cargo build` has not been run yet (after a `cargo clean`),
                // the `build.rs` script won't have generated libdhcp.so, so lets
                // do it ourselves.
                println!(
                    "Could not find Kea hooks dynamic library in any of {candidates:?}. Building."
                );
                test_cdylib::build_current_project();
                candidates
                    .into_iter()
                    .find(|p| Path::new(p).exists())
                    .expect("test_cdylib build did not produce libdhcp.so at any expected path")
            }
        };

        let conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": [ "lo" ],
                "dhcp-socket-type": "udp"
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": lease_file.to_string_lossy(),
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
                        "carbide-metrics-endpoint": "[::]:0",
                            "carbide-nameservers": "1.1.1.1,8.8.8.8",
                            "carbide-provisioning-server-ipv4": "127.0.0.1"
                        }
                }
            ],
            "subnet4": [
                {
                    "subnet": "0.0.0.0/0",
                    "pools": [{
                        "pool": "0.0.0.1-255.255.255.254"
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
