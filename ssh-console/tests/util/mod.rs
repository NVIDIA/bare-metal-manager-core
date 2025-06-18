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
use crate::util::machine_a_tron::MachineATronTestHandle;
use crate::util::ssh_client::ConnectionConfig;
use crate::{TENANT_SSH_KEY_PATH, TENANT_SSH_PUBKEY};
use api_test_helper::utils::{ApiServerHandle, REPO_ROOT, start_api_server};
use api_test_helper::{IntegrationTestEnvironment, domain, subnet, tenant, vpc};
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use temp_dir::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

pub mod ipmi_sim;
pub mod legacy;
pub mod machine_a_tron;
pub mod ssh_client;

lazy_static::lazy_static! {
    pub static ref BMC_MOCK_CERTS_DIR: PathBuf = REPO_ROOT
        .join("dev/bmc-mock")
        .canonicalize()
        .unwrap();
    pub static ref LOCALHOST_CERTS_DIR: PathBuf = REPO_ROOT
        .join("dev/certs/localhost")
        .canonicalize()
        .unwrap();
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

pub fn should_run_integration_tests() -> bool {
    env::var("RUN_SSH_CONSOLE_TESTS")
        .map(|s| s == "1")
        .unwrap_or(false)
}

/// Runs a baseline test environment for comparing results for leagacy ssh-console and (soon) new
/// ssh-console. Adds to api_test_helper's IntegrationTestEnvironment by running an ipmi_sim and a
/// machine-a-tron environment with 2 machines. Also creates tenants/orgs/instances.
pub async fn run_baseline_test_environment() -> eyre::Result<Option<BaselineTestEnvironment>> {
    if !should_run_integration_tests() {
        tracing::info!("Skipping ssh-console tests, RUN_SSH_CONSOLE_TESTS is not set");
        return Ok(None);
    }
    let Some(test_env) = IntegrationTestEnvironment::try_from_environment(1).await? else {
        return Ok(None);
    };

    let carbide_api_addrs = test_env.carbide_api_addrs.clone();

    // Run ipmi_sim
    let ipmi_sim_handle = ipmi_sim::run().await?;

    // Run carbide-api
    let empty_firmware_dir = temp_dir::TempDir::with_prefix("firmware")?;
    let api_server_handle = start_api_server(
        test_env.clone(),
        None,
        empty_firmware_dir.path().to_path_buf(),
        0,
        false,
    )
    .await?;

    // Create VPC/tenant/etc
    let org_id = "MyOrg";
    let tenant_keyset_id = Uuid::new_v4();
    tenant::create(&carbide_api_addrs, org_id, "tenant-1").await?;
    tenant::keyset::create(
        &carbide_api_addrs,
        org_id,
        tenant_keyset_id,
        &[TENANT_SSH_PUBKEY],
    )
    .await?;
    let tenant1_vpc = vpc::create(&carbide_api_addrs).await?;
    let domain_id = domain::create(&carbide_api_addrs, "tenant-1.local").await?;
    subnet::create(&carbide_api_addrs, &tenant1_vpc, &domain_id, 11, true).await?;
    let managed_segment_id =
        subnet::create(&carbide_api_addrs, &tenant1_vpc, &domain_id, 10, false).await?;

    // Run machine-a-tron to get working host/dpus with their own mock BMC's
    let mat_handle = machine_a_tron::run(
        2,
        carbide_api_addrs[0].port(),
        Ipv4Addr::new(10, 10, 11, 2),
        &managed_segment_id,
        &[&tenant_keyset_id.to_string()],
    )
    .await?;

    Ok(Some(BaselineTestEnvironment {
        mat_handle,
        test_env,
        _api_server_handle: api_server_handle,
        _empty_firmware_dir: empty_firmware_dir,
        _ipmi_sim_handle: ipmi_sim_handle,
    }))
}

pub struct BaselineTestEnvironment {
    pub mat_handle: MachineATronTestHandle,
    pub test_env: IntegrationTestEnvironment,
    _api_server_handle: ApiServerHandle,
    _empty_firmware_dir: TempDir,
    _ipmi_sim_handle: IpmiSimHandle,
}

impl BaselineTestEnvironment {
    pub async fn run_baseline_assertions(
        &self,
        addr: SocketAddr,
        connection_name: &str,
    ) -> eyre::Result<()> {
        // Test each machine through legacy ssh-console
        for (i, machine) in self.mat_handle.machines.iter().enumerate() {
            let machine_id = machine.observed_machine_id().unwrap().id;
            let instance_id = &self.mat_handle.instance_ids[i];
            let expected_prompt = format!("root@{} # ", machine_id);

            ssh_client::assert_connection_works_with_retries_and_timeout(
                ConnectionConfig {
                    connection_name: "legacy ssh-console to host",
                    user: &machine_id,
                    private_key_path: &TENANT_SSH_KEY_PATH,
                    addr,
                    expected_prompt: &expected_prompt,
                },
                // The legacy ssh-console tends to take a few retries right after it boots up. After the
                // first machine works, don't do any more retries.
                if i == 0 { 5 } else { 0 },
                Duration::from_secs(10),
            )
            .await?;

            // Then try connecting with instance_id as the username
            ssh_client::assert_connection_works_with_retries_and_timeout(
                ConnectionConfig {
                    connection_name,
                    user: instance_id,
                    private_key_path: &TENANT_SSH_KEY_PATH,
                    addr,
                    expected_prompt: &expected_prompt,
                },
                0, // It already worked once, we shouldn't need to retry
                Duration::from_secs(10),
            )
            .await?;
        }

        Ok(())
    }
}
