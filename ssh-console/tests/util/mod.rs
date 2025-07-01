/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::util::ipmi_sim::IpmiSimHandle;
use crate::util::ssh_client::ConnectionConfig;
use crate::{ADMIN_SSH_KEY_PATH, TENANT_SSH_KEY_PATH, TENANT_SSH_PUBKEY};
use bmc_mock::HostnameQuerying;
use eyre::Context;
use forge_uuid::machine::{MachineIdSource, MachineType};
use futures::future::join_all;
use machine_a_tron::MockSshServerHandle;
use ssh_console_mock_api_server::{MockApiServerHandle, MockHost};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

pub mod ipmi_sim;
pub mod legacy;
pub mod ssh_client;

pub mod fixtures {
    use api_test_helper::utils::REPO_ROOT;
    use std::path::PathBuf;

    lazy_static::lazy_static! {
        pub static ref BMC_MOCK_CERTS_DIR: PathBuf = REPO_ROOT
            .join("dev/bmc-mock")
            .canonicalize()
            .unwrap();
        pub static ref LOCALHOST_CERTS_DIR: PathBuf = REPO_ROOT
            .join("dev/certs/localhost")
            .canonicalize()
            .unwrap();
        pub static ref SSH_HOST_PUBKEY: PathBuf = REPO_ROOT
            .join("ssh-console/tests/fixtures/ssh_host_ed25519_key.pub")
            .canonicalize()
            .unwrap();
        pub static ref AUTHORIZED_KEYS_PATH: PathBuf = REPO_ROOT
            .join("ssh-console/tests/fixtures/authorized_keys")
            .canonicalize()
            .unwrap();
        pub static ref SSH_HOST_KEY: PathBuf = REPO_ROOT
            .join("ssh-console/tests/fixtures/ssh_host_ed25519_key")
            .canonicalize()
            .unwrap();
        pub static ref API_CA_CERT: PathBuf = REPO_ROOT
            .join("dev/certs/localhost/ca.crt")
            .canonicalize()
            .unwrap();
        pub static ref API_CLIENT_CERT: PathBuf = REPO_ROOT
            .join("dev/certs/localhost/client.crt")
            .canonicalize()
            .unwrap();
        pub static ref API_CLIENT_KEY: PathBuf = REPO_ROOT
            .join("dev/certs/localhost/client.key")
            .canonicalize()
            .unwrap();
    }
}

pub fn log_stdout_and_stderr(process: &mut tokio::process::Child, prefix: &str) {
    let stdout = process.stdout.take().unwrap();
    let stderr = process.stderr.take().unwrap();
    let prefix = prefix.to_string();

    tokio::spawn(async move {
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);
        let mut stdout_lines = stdout_reader.lines();
        let mut stderr_lines = stderr_reader.lines();
        loop {
            tokio::select! {
                Ok(Some(line)) = stdout_lines.next_line() => {
                    tracing::info!("[{prefix} STDOUT] {line}")
                }
                Ok(Some(line)) = stderr_lines.next_line() => {
                    // stderr can be logged as info, because in practice ssh-console logs everything to stderr.
                    tracing::info!("[{prefix} STDERR] {line}")
                }
                else => break,
            }
        }
    });
}

/// Runs a baseline test environment for comparing results for leagacy ssh-console and (soon) new
/// ssh-console. Adds to api_test_helper's IntegrationTestEnvironment by running an ipmi_sim and a
/// machine-a-tron environment with 2 machines. Also creates tenants/orgs/instances.
pub async fn run_baseline_test_environment(
    machine_count: u8,
) -> eyre::Result<Option<BaselineTestEnvironment>> {
    // Run ipmi_sim
    let ipmi_sim_handle = ipmi_sim::run().await?;

    let machine_ids = (0..machine_count)
        .map(|_| {
            forge_uuid::machine::MachineId::new(
                MachineIdSource::Tpm,
                rand::random(),
                MachineType::Host,
            )
        })
        .collect::<Vec<_>>();

    let ssh_server_handles: Vec<MockSshServerHandle> = join_all((0..machine_count).map(|i| {
        machine_a_tron::spawn_mock_ssh_server(
            IpAddr::from_str("127.0.0.1").unwrap(),
            None,
            Arc::new(KnownHostname(machine_ids[i as usize].to_string())),
            "root".to_string(),
            "password".to_string(),
        )
    }))
    .await
    .into_iter()
    .collect::<Result<_, _>>()
    .context("Error spawning mock SSH server")?;

    let mock_hosts: Vec<MockHost> = machine_ids
        .iter()
        .enumerate()
        .map(|(i, machine_id)| MockHost {
            machine_id: *machine_id,
            instance_id: Uuid::new_v4(),
            tenant_public_key: TENANT_SSH_PUBKEY.to_string(),
            sys_vendor: "Dell".to_string(),
            bmc_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bmc_ssh_port: ssh_server_handles[i].port,
            bmc_user: "root".to_string(),
            bmc_password: "password".to_string(),
        })
        .collect();

    let api_server_handle = ssh_console_mock_api_server::MockApiServer {
        mock_hosts: mock_hosts.clone(),
    }
    .spawn()
    .await
    .context("error spawning mock API server")?;

    Ok(Some(BaselineTestEnvironment {
        mock_api_server: api_server_handle,
        mock_ssh_servers: ssh_server_handles,
        mock_hosts,
        _ipmi_sim_handle: ipmi_sim_handle,
    }))
}

#[derive(Debug)]
struct KnownHostname(String);

impl HostnameQuerying for KnownHostname {
    fn get_hostname(&self) -> String {
        self.0.clone()
    }
}

pub struct BaselineTestEnvironment {
    pub mock_api_server: MockApiServerHandle,
    pub mock_hosts: Vec<MockHost>,
    pub mock_ssh_servers: Vec<MockSshServerHandle>,
    _ipmi_sim_handle: IpmiSimHandle,
}

impl BaselineTestEnvironment {
    pub async fn run_baseline_assertions(
        &self,
        addr: SocketAddr,
        connection_name: &str,
        assertions: &[BaselineTestAssertion],
    ) -> eyre::Result<()> {
        // Test each machine through legacy ssh-console
        for (i, mock_host) in self.mock_hosts.iter().enumerate() {
            let expected_prompt = format!("root@{} # ", mock_host.machine_id).into_bytes();

            for assertion in assertions {
                match assertion {
                    BaselineTestAssertion::ConnectAsMachineId => {
                        ssh_client::assert_connection_works_with_retries_and_timeout(
                            ConnectionConfig {
                                connection_name: &format!("{connection_name} to host").to_string(),
                                user: &mock_host.machine_id.to_string(),
                                private_key_path: &ADMIN_SSH_KEY_PATH,
                                addr,
                                expected_prompt: &expected_prompt,
                            },
                            // The legacy ssh-console tends to take a few retries right after it boots up. After the
                            // first machine works, don't do any more retries.
                            if i == 0 { 5 } else { 0 },
                            Duration::from_secs(10),
                        )
                        .await?;

                        // Make sure it *doesn't* work as the tenant user.
                        let result_as_tenant =
                            ssh_client::assert_connection_works(ConnectionConfig {
                                connection_name: &format!("{connection_name} to host").to_string(),
                                user: &mock_host.machine_id.to_string(),
                                private_key_path: &TENANT_SSH_KEY_PATH,
                                addr,
                                expected_prompt: &expected_prompt,
                            })
                            .await;

                        if result_as_tenant.is_ok() {
                            return Err(eyre::format_err!(
                                "Connection directly to machine_id succeeded as tenant, it should have failed"
                            ));
                        }
                    }
                    BaselineTestAssertion::ConnectAsInstanceId => {
                        ssh_client::assert_connection_works_with_retries_and_timeout(
                            ConnectionConfig {
                                connection_name: &format!("{connection_name} to instance")
                                    .to_string(),
                                user: &mock_host.instance_id.to_string(),
                                private_key_path: &TENANT_SSH_KEY_PATH,
                                addr,
                                expected_prompt: &expected_prompt,
                            },
                            0, // It already worked once, we shouldn't need to retry
                            Duration::from_secs(10),
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
pub enum BaselineTestAssertion {
    #[allow(dead_code)]
    ConnectAsMachineId,
    ConnectAsInstanceId,
}
