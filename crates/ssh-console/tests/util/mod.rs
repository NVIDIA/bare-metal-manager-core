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
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bmc_mock::HostnameQuerying;
use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use eyre::Context;
use futures::future::join_all;
use futures_util::future::BoxFuture;
use machine_a_tron::{MockSshServerHandle, PromptBehavior};
use ssh_console_mock_api_server::{MockApiServerHandle, MockHost};
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

use crate::util::ipmi_sim::IpmiSimHandle;
use crate::util::metrics::assert_metrics;
use crate::util::ssh_client::ConnectionConfig;
use crate::{ADMIN_SSH_KEY_PATH, TENANT_SSH_KEY_PATH, TENANT_SSH_PUBKEY};

pub mod ipmi_sim;
mod metrics;
pub mod ssh_client;
pub mod ssh_console_test_helper;

pub mod fixtures {
    use std::path::PathBuf;

    use api_test_helper::utils::REPO_ROOT;

    lazy_static::lazy_static! {
        pub static ref BMC_MOCK_CERTS_DIR: PathBuf = REPO_ROOT
            .join("crates/bmc-mock")
            .canonicalize()
            .unwrap();
        pub static ref LOCALHOST_CERTS_DIR: PathBuf = REPO_ROOT
            .join("dev/certs/localhost")
            .canonicalize()
            .unwrap();
        pub static ref SSH_HOST_PUBKEY: PathBuf = REPO_ROOT
            .join("crates/ssh-console/tests/fixtures/ssh_host_ed25519_key.pub")
            .canonicalize()
            .unwrap();
        pub static ref AUTHORIZED_KEYS_PATH: PathBuf = REPO_ROOT
            .join("crates/ssh-console/tests/fixtures/authorized_keys")
            .canonicalize()
            .unwrap();
        pub static ref SSH_HOST_KEY: PathBuf = REPO_ROOT
            .join("crates/ssh-console/tests/fixtures/ssh_host_ed25519_key")
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
    machines: Vec<MockBmcType>,
) -> eyre::Result<Option<BaselineTestEnvironment>> {
    let mock_bmc_handles: Vec<(MockBmcHandle, MachineId)> =
        join_all(machines.iter().map(|bmc_type| {
            // Generate random machine ID's for each mocked host
            let machine_id = carbide_uuid::machine::MachineId::new(
                MachineIdSource::Tpm,
                rand::random(),
                match bmc_type {
                    MockBmcType::Ssh | MockBmcType::Ipmi => MachineType::Host,
                    MockBmcType::DpuSsh => MachineType::Dpu,
                },
            );

            async move {
                let bmc_handle = match bmc_type {
                    ssh_type @ MockBmcType::Ssh | ssh_type @ MockBmcType::DpuSsh => {
                        Ok::<MockBmcHandle, eyre::Error>(MockBmcHandle::Ssh(
                            machine_a_tron::spawn_mock_ssh_server(
                                IpAddr::from_str("127.0.0.1").unwrap(),
                                None,
                                Arc::new(KnownHostname(machine_id.to_string())),
                                Some(machine_a_tron::MockSshCredentials {
                                    user: "root".to_string(),
                                    password: "password".to_string(),
                                }),
                                match ssh_type {
                                    MockBmcType::Ssh => PromptBehavior::Dell,
                                    MockBmcType::DpuSsh => PromptBehavior::Dpu,
                                    MockBmcType::Ipmi => unreachable!(),
                                },
                            )
                            .await?,
                        ))
                    }
                    MockBmcType::Ipmi => Ok(MockBmcHandle::Ipmi(
                        ipmi_sim::run(format!("root@{machine_id} # ")).await?,
                    )),
                }?;

                Ok::<_, eyre::Error>((bmc_handle, machine_id))
            }
        }))
        .await
        .into_iter()
        .collect::<Result<_, _>>()
        .context("Error spawning mock SSH server")?;

    let mock_hosts: Arc<Vec<MockHost>> = Arc::new(
        mock_bmc_handles
            .iter()
            .map(|(bmc_handle, machine_id)| MockHost {
                machine_id: *machine_id,
                instance_id: Uuid::new_v4(),
                tenant_public_key: TENANT_SSH_PUBKEY.to_string(),
                sys_vendor: match &bmc_handle {
                    MockBmcHandle::Ssh(_) => "Dell",
                    MockBmcHandle::Ipmi(_) => "Supermicro",
                },
                bmc_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                bmc_ssh_port: match &bmc_handle {
                    MockBmcHandle::Ssh(s) => Some(s.port),
                    MockBmcHandle::Ipmi(_) => None,
                },
                ipmi_port: match &bmc_handle {
                    MockBmcHandle::Ssh(_) => None,
                    MockBmcHandle::Ipmi(i) => Some(i.port),
                },
                bmc_user: "root".to_string(),
                bmc_password: "password".to_string(),
            })
            .collect(),
    );

    tracing::debug!("baseline test mock hosts: {mock_hosts:?}");

    let api_server_handle = ssh_console_mock_api_server::MockApiServer {
        mock_hosts: mock_hosts.clone(),
    }
    .spawn()
    .await
    .context("error spawning mock API server")?;

    Ok(Some(BaselineTestEnvironment {
        mock_api_server: api_server_handle,
        _mock_bmc_handles: mock_bmc_handles
            .into_iter()
            .map(|(handle, _machine_id)| handle)
            .collect(),
        mock_hosts,
    }))
}

#[derive(Debug, Clone, Copy)]
pub enum MockBmcType {
    Ssh,
    DpuSsh,
    Ipmi,
}

pub enum MockBmcHandle {
    Ssh(MockSshServerHandle),
    Ipmi(IpmiSimHandle),
}

#[derive(Debug)]
struct KnownHostname(String);

impl HostnameQuerying for KnownHostname {
    fn get_hostname(&'_ self) -> Cow<'_, str> {
        Cow::Borrowed(self.0.as_str())
    }
}

pub struct BaselineTestEnvironment {
    pub mock_api_server: MockApiServerHandle,
    pub mock_hosts: Arc<Vec<MockHost>>,
    _mock_bmc_handles: Vec<MockBmcHandle>,
}

impl BaselineTestEnvironment {
    pub async fn run_baseline_assertions<MetricsFn>(
        &self,
        addr: SocketAddr,
        connection_name: &str,
        assertions: &[BaselineTestAssertion],
        get_metrics: MetricsFn,
        test_reboot_command: bool,
    ) -> eyre::Result<()>
    where
        MetricsFn: FnOnce() -> Option<BoxFuture<'static, eyre::Result<String>>>,
    {
        // Test each machine through legacy ssh-console
        for (i, mock_host) in self.mock_hosts.iter().enumerate() {
            let expected_prompt = format!("root@{} # ", mock_host.machine_id).into_bytes();

            for assertion in assertions {
                match assertion {
                    BaselineTestAssertion::ConnectAsMachineId => {
                        let connection_config = ConnectionConfig {
                            connection_name: &format!("{connection_name} to host").to_string(),
                            user: &mock_host.machine_id.to_string(),
                            private_key_path: &ADMIN_SSH_KEY_PATH,
                            addr,
                            expected_prompt: &expected_prompt,
                        };

                        ssh_client::assert_connection_works_with_retries_and_timeout(
                            &connection_config,
                            // The legacy ssh-console tends to take a few retries right after it boots up. After the
                            // first machine works, don't do any more retries.
                            if i == 0 { 5 } else { 0 },
                            Duration::from_secs(30),
                        )
                        .await?;

                        if test_reboot_command {
                            ssh_client::assert_reboot_behavior(
                                &connection_config,
                                mock_host.sys_vendor.to_lowercase() == "supermicro",
                            )
                            .await
                            .with_context(|| {
                                format!(
                                    "error asserting reboot behavior for {}",
                                    mock_host.sys_vendor
                                )
                            })?;
                        }

                        // Make sure it *doesn't* work as the tenant user.
                        let result_as_tenant =
                            ssh_client::assert_connection_works(&ConnectionConfig {
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
                        let connection_config = ConnectionConfig {
                            connection_name: &format!("{connection_name} to instance").to_string(),
                            user: &mock_host.instance_id.to_string(),
                            private_key_path: &TENANT_SSH_KEY_PATH,
                            addr,
                            expected_prompt: &expected_prompt,
                        };

                        ssh_client::assert_connection_works_with_retries_and_timeout(
                            &connection_config,
                            0, // It already worked once, we shouldn't need to retry
                            Duration::from_secs(10),
                        )
                        .await?;

                        if test_reboot_command {
                            ssh_client::assert_reboot_behavior(
                                &connection_config,
                                mock_host.sys_vendor.to_lowercase() == "supermicro",
                            )
                            .await
                            .with_context(|| {
                                format!(
                                    "error asserting reboot behavior for {}",
                                    mock_host.sys_vendor
                                )
                            })?;
                        }
                    }
                    BaselineTestAssertion::FillLogsAsMachineId(bytes) => {
                        let connection_config = ConnectionConfig {
                            connection_name: &format!("{connection_name} to host").to_string(),
                            user: &mock_host.machine_id.to_string(),
                            private_key_path: &ADMIN_SSH_KEY_PATH,
                            addr,
                            expected_prompt: &expected_prompt,
                        };

                        ssh_client::fill_logs(&connection_config, *bytes).await?;
                    }
                }
            }
        }

        if let Some(metrics_fut) = get_metrics() {
            let metrics = Box::pin(metrics_fut)
                .await
                .context("Error getting metrics")?;
            assert_metrics(metrics, self.mock_hosts.as_slice()).await?;
        }

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
pub enum BaselineTestAssertion {
    ConnectAsMachineId,
    ConnectAsInstanceId,
    FillLogsAsMachineId(usize),
}
