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
use cfg::{AutoDetect, Command, Mode, Options};
use clap::CommandFactory;
use once_cell::sync::Lazy;
use rpc::forge::forge_agent_control_response::Action;
use rpc::{forge as rpc_forge, ForgeScoutErrorReport};
pub use scout::{CarbideClientError, CarbideClientResult};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::sync::RwLock;
use tryhard::RetryFutureConfig;

mod attestation;
mod cfg;
mod client;
mod deprovision;
mod discovery;
mod ipmi;
mod machine_validation;
mod register;
mod users;
struct DevEnv {
    in_qemu: bool,
}
static IN_QEMU_VM: Lazy<RwLock<DevEnv>> = Lazy::new(|| RwLock::new(DevEnv { in_qemu: false }));
const POLL_INTERVAL: Duration = Duration::from_secs(60);
pub const REBOOT_COMPLETED_PATH: &str = "/tmp/reboot_completed";

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
    if config.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    check_if_running_in_qemu().await;

    forge_host_support::init_logging()?;

    tracing::info!("Running as {}...{}", config.mode, config.version);

    match config.mode {
        Mode::Service => run_as_service(&config).await?,
        Mode::Standalone => run_standalone(&config).await?,
    }
    Ok(())
}

async fn initial_setup(config: &Options) -> Result<String, eyre::Report> {
    let machine_id = match register::run(
        &config.api,
        config.root_ca.clone(),
        config.machine_interface_id,
        config.discovery_retry_secs,
        config.discovery_retries_max,
        &config.tpm_path,
    )
    .await
    {
        Ok(machine_id) => machine_id,
        Err(e) => {
            report_scout_error(config, None, config.machine_interface_id, &e).await?;
            return Err(e.into());
        }
    };

    if !Path::new(REBOOT_COMPLETED_PATH).exists() {
        discovery::rebooted(config, &machine_id).await?;
        let mut data_file = File::create(REBOOT_COMPLETED_PATH).expect("creation failed");
        data_file.write_all(format!("Reboot completed at {}", chrono::Utc::now()).as_bytes())?;
    }
    Ok(machine_id)
}

async fn run_as_service(config: &Options) -> Result<(), eyre::Report> {
    // Implement the logic to run as a service here
    let machine_id = initial_setup(config).await?;
    loop {
        let action = match query_api_with_retries(config, &machine_id).await {
            Ok(action) => action,
            Err(e) => {
                report_scout_error(config, None, config.machine_interface_id, &e).await?;
                Action::Noop
            }
        };
        match handle_action(action, &machine_id, config.machine_interface_id, config).await {
            Ok(_) => tracing::info!("Successfully served {}", action.as_str_name()),
            Err(e) => tracing::info!("Failed to serve {}: Err {}", action.as_str_name(), e),
        };
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn run_standalone(config: &Options) -> Result<(), eyre::Report> {
    // Implement the logic for standalone mode here
    let subcmd = match &config.subcmd {
        None => {
            Options::command().print_long_help()?;
            std::process::exit(1);
        }
        Some(s) => s,
    };
    let machine_id = initial_setup(config).await?;
    //TODO Could be better; this for backward compatibility. Refactor required
    let action = match query_api_with_retries(config, &machine_id).await {
        Ok(action) => action,
        Err(e) => {
            report_scout_error(config, None, config.machine_interface_id, &e).await?;
            Action::Noop
        }
    };
    let action = match subcmd {
        Command::AutoDetect(AutoDetect { .. }) => action,
        Command::Deprovision(_) => Action::Reset,
        Command::Discovery(_) => Action::Discovery,
        Command::Reset(_) => Action::Reset,
        Command::Logerror(_) => Action::Logerror,
    };

    handle_action(action, &machine_id, config.machine_interface_id, config).await?;
    Ok(())
}
async fn handle_action(
    action: Action,
    machine_id: &str,
    machine_interface_id: uuid::Uuid,
    config: &Options,
) -> Result<(), CarbideClientError> {
    match action {
        Action::Discovery => {
            // This is temporary. All cleanup must be done when API call Reset.
            deprovision::run_no_api();

            let result = discovery::run(config, machine_id).await;
            discovery::completed(config, machine_id, result.err().map(|e| e.to_string())).await?;
        }
        Action::Reset => {
            deprovision::run(config, machine_id).await?;
        }
        Action::Rebuild => {
            unimplemented!("Rebuild not written yet");
        }
        Action::Noop => {}
        Action::Logerror => match logerror_to_carbide(config, machine_interface_id).await {
            Ok(()) => (),
            Err(e) => tracing::info!("Forge Scout logerror_to_carbide error: {}", e),
        },
        Action::Retry => {
            panic!("Retrieved Retry action, which should be handled internally by query_api_with_retries");
        }
        Action::Measure => {
            attestation::run(config, machine_id).await?;
        }
        Action::MachineValidation => {
            tracing::info!("Machine validationstub code");
            machine_validation::completed(config, machine_id, None).await?;
        }
    }
    Ok(())
}

// Return the last 1500 bytes of the cloud-init-output.log file as a String
fn get_log_str() -> eyre::Result<String> {
    let mut ret_str = String::new();

    let text = std::fs::read_to_string("/var/log/cloud-init-output.log")?;

    for line in text.lines().rev() {
        let line_str = format!("{}\n", line);
        ret_str.insert_str(0, &line_str);
        if ret_str.len() > ::rpc::MAX_ERR_MSG_SIZE as usize {
            break;
        }
    }

    Ok(ret_str)
}

// Send error string to carbide api to log, indicating that the cloud-init script failed.
// Very similar to report_scout_error below, but is run before discovery is done.
async fn logerror_to_carbide(
    config: &Options,
    machine_interface_id: uuid::Uuid,
) -> eyre::Result<()> {
    let err_str = get_log_str()?;
    let request: tonic::Request<ForgeScoutErrorReport> =
        tonic::Request::new(ForgeScoutErrorReport {
            machine_id: None,
            machine_interface_id: Some(machine_interface_id.into()),
            error: err_str,
        });

    let mut client = client::create_forge_client(config).await?;
    let _response = client.report_forge_scout_error(request).await?;

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
async fn query_api(
    config: &Options,
    machine_id: &str,
    action_attempt: u64,
    query_attempt: u64,
) -> CarbideClientResult<Action> {
    tracing::info!(
        "Sending ForgeAgentControlRequest (attempt:{}.{})",
        action_attempt,
        query_attempt,
    );
    let query = rpc_forge::ForgeAgentControlRequest {
        machine_id: Some(machine_id.to_string().into()),
    };
    let request = tonic::Request::new(query);
    let mut client = client::create_forge_client(config).await?;
    let response = client.forge_agent_control(request).await?.into_inner();
    let action = Action::try_from(response.action)
        .map_err(|err| CarbideClientError::RpcDecodeError(err.to_string()))?;
    tracing::info!(
        "Received ForgeAgentControlResponse (attempt:{}.{}, action:{})",
        action_attempt,
        query_attempt,
        action.as_str_name()
    );
    Ok(action)
}

async fn query_api_with_retries(config: &Options, machine_id: &str) -> CarbideClientResult<Action> {
    let mut action_attempt = 0;
    const MAX_RETRY_COUNT: u64 = 5;
    const RETRY_TIMER: u64 = 30;

    // The retry_config currently leverages the discovery_retry_*
    // flags passed in via the Scout command line, since this also
    // seems like a similar case where it should be persistent but
    // not aggressive. If there ends up being a desire to also have a
    // similar set of control_retry_* flags in the CLI, we can do
    // that (but trying to limit the number of flags if possible).
    let retry_config = RetryFutureConfig::new(config.discovery_retries_max)
        .fixed_backoff(Duration::from_secs(config.discovery_retry_secs));

    // State machine handler needs 1-2 cycles to update host_adminIP to leaf.
    // In case by the time, host comes up and IP is still not updated, let's wait.
    loop {
        // Depending on the forge_agent_control_response Action received
        // this entire loop may need to retry (as in, an Action::Retry was
        // received).
        //
        // BUT, that's in the case of the API call being successful (where
        // an Action is successfully returned). If the query_api attempt
        // itself fails, then IT needs to be retried as well, so query_api
        // also gets wrapped with a retry. Keep an inner attempt counter for
        // the purpose of tracing -- it seems helpful to know where in the
        // attempts thing sare.
        let mut query_attempt = 0u64;
        let action = tryhard::retry_fn(|| {
            query_attempt += 1;
            query_api(config, machine_id, action_attempt, query_attempt)
        })
        .with_config(retry_config)
        .await?;

        action_attempt += 1;

        if action != Action::Retry {
            return Ok(action);
        }

        // +1 for the initial attempt which happens immediately
        if action_attempt == 1 + MAX_RETRY_COUNT {
            return Err(CarbideClientError::GenericError(format!(
                "Retrieved no viable Action for machine {} after {} secs",
                machine_id,
                MAX_RETRY_COUNT * RETRY_TIMER
            )));
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_TIMER)).await;
    }
}
