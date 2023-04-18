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
use cfg::{AutoDetect, Command, Options};
use log::LevelFilter;
use once_cell::sync::Lazy;
use rpc::forge::forge_agent_control_response::Action;
use rpc::{forge as rpc_forge, ForgeScoutErrorReport};
pub use scout::{CarbideClientError, CarbideClientResult};
use tokio::sync::RwLock;

mod cfg;
mod client;
mod deprovision;
mod discovery;
mod ipmi;
mod register;
mod users;

struct DevEnv {
    in_qemu: bool,
}
static IN_QEMU_VM: Lazy<RwLock<DevEnv>> = Lazy::new(|| RwLock::new(DevEnv { in_qemu: false }));

async fn check_if_running_in_qemu() {
    use tokio::process::Command;
    let output = match Command::new("systemd-detect-virt").output().await {
        Ok(s) => s,
        Err(_) => {
            // Not sure. But if above command is not present,
            // assume it real machine.
            return;
        }
    };

    if let Ok(x) = String::from_utf8(output.stdout) {
        if x.trim() != "none" {
            IN_QEMU_VM.write().await.in_qemu = true;
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), eyre::Report> {
    let config = Options::load();
    check_if_running_in_qemu().await;

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                // command line overrides config file
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Debug
            }
            _ => {
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Trace
            }
        })
        .init();

    let machine_interface_id = config.subcmd.machine_interface_id();
    let machine_id =
        match register::run(&config.api, config.root_ca.clone(), machine_interface_id).await {
            Ok(machine_id) => machine_id,
            Err(e) => {
                report_scout_error(&config, None, machine_interface_id, &e).await?;
                return Err(e.into());
            }
        };

    let action = match config.subcmd {
        Command::AutoDetect(AutoDetect { .. }) => {
            match query_api_with_retries(&config, &machine_id).await {
                Ok(action) => action,
                Err(e) => {
                    report_scout_error(&config, Some(machine_id), machine_interface_id, &e).await?;
                    return Err(e.into());
                }
            }
        }
        Command::Deprovision(_) => Action::Reset,
    };

    if let Err(e) = handle_action(action, &machine_id, &config).await {
        report_scout_error(&config, Some(machine_id), machine_interface_id, &e).await?;
        return Err(e.into());
    }

    Ok(())
}

async fn handle_action(
    action: Action,
    machine_id: &str,
    config: &Options,
) -> Result<(), CarbideClientError> {
    match action {
        Action::Discovery => {
            // This is temporary. All cleanup must be done when API call Reset.
            deprovision::run_no_api();

            discovery::run(config, machine_id).await?;
            discovery::completed(config, machine_id).await?;
        }
        Action::Reset => {
            deprovision::run(config, machine_id).await?;
        }
        Action::Rebuild => {
            unimplemented!("Rebuild not written yet");
        }
        Action::Noop => {}
        Action::Retry => {
            panic!("Retrieved Retry action, which should be handled internally by query_api_with_retries");
        }
    }
    Ok(())
}

async fn report_scout_error(
    config: &Options,
    machine_id: Option<String>,
    machine_interface_id: uuid::Uuid,
    error: &impl std::error::Error,
) -> CarbideClientResult<()> {
    let request: tonic::Request<ForgeScoutErrorReport> =
        tonic::Request::new(ForgeScoutErrorReport {
            machine_id: machine_id.map(|id| id.into()),
            machine_interface_id: Some(machine_interface_id.into()),
            error: format!("{error:#}"), // Alternate representation also prints inner errors
        });

    let mut client = client::create_forge_client(config).await?;
    let _response = client.report_forge_scout_error(request).await?.into_inner();
    Ok(())
}

/// Ask API if we need to do anything after discovery.
async fn query_api(config: &Options, machine_id: &str) -> CarbideClientResult<Action> {
    let query = rpc_forge::ForgeAgentControlRequest {
        machine_id: Some(machine_id.to_string().into()),
    };
    let request = tonic::Request::new(query);
    let mut client = client::create_forge_client(config).await?;
    let response = client.forge_agent_control(request).await?.into_inner();
    let action = Action::try_from(response.action)?;
    Ok(action)
}

async fn query_api_with_retries(config: &Options, machine_id: &str) -> CarbideClientResult<Action> {
    let mut attempts = 0;
    const MAX_RETRY_COUNT: u64 = 5;
    const RETRY_TIMER: u64 = 30;

    // State machine handler needs 1-2 cycles to update host_adminIP to leaf.
    // In case by the time, host coems up and IP is still not updated, let's wait.
    loop {
        let action = query_api(config, machine_id).await?;
        attempts += 1;

        if action != Action::Retry {
            return Ok(action);
        }

        // +1 for the initial attempt which happens immediately
        if attempts == 1 + MAX_RETRY_COUNT {
            return Err(CarbideClientError::GenericError(format!(
                "Retrieved no Action for machine {} after {} secs",
                machine_id,
                MAX_RETRY_COUNT * RETRY_TIMER
            )));
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_TIMER)).await;
    }
}
