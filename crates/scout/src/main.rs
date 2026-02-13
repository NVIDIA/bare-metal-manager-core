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
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use carbide_host_support::dpa_cmds::{DpaCommand, OpCode};
use carbide_host_support::registration;
use carbide_uuid::machine::MachineId;
use cfg::{AutoDetect, Command, MlxAction, Mode, Options};
use chrono::{DateTime, Days, TimeDelta, Utc};
use clap::CommandFactory;
use libmlx::device::cmd::device::args::DeviceArgs;
use libmlx::device::cmd::device::cmds::handle as handle_mlx_device;
use libmlx::device::discovery::discover_device;
use libmlx::lockdown::cmd::cmds::handle_lockdown as handle_mlx_lockdown;
use once_cell::sync::Lazy;
use rpc::forge::ForgeAgentControlResponse;
use rpc::forge::forge_agent_control_response::{Action, ForgeAgentControlExtraInfo};
use rpc::forge_agent_control_response::forge_agent_control_extra_info::KeyValuePair;
use rpc::protos::mlx_device::{
    LockStatus, MlxObservation, MlxObservationReport, PublishMlxObservationReportRequest,
};
use rpc::{ForgeScoutErrorReport, forge as rpc_forge};
pub use scout::{CarbideClientError, CarbideClientResult};
use tokio::sync::RwLock;
use tryhard::{RetryFutureConfig, RetryPolicy};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

mod attestation;
mod cfg;
mod client;
mod deprovision;
mod discovery;
mod machine_validation;
mod mlx_device;
mod register;
mod stream;

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

    if let Ok(x) = String::from_utf8(output.stdout)
        && x.trim() != "none"
    {
        IN_QEMU_VM.write().await.in_qemu = true;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), eyre::Report> {
    let config = Options::load();
    if config.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }

    check_if_running_in_qemu().await;

    carbide_host_support::init_logging()?;

    tracing::info!("Running as {}...{}", config.mode, config.version);

    match config.mode {
        Mode::Service => run_as_service(&config).await?,
        Mode::Standalone => run_standalone(&config).await?,
    }
    Ok(())
}

async fn initial_setup(config: &Options) -> Result<(uuid::Uuid, MachineId), eyre::Report> {
    // we use the same retry params for both: retrying the discover_machine
    // call, as well as retrying the whole attestation sequence: discover_machine + attest_quote
    let retry = registration::DiscoveryRetry {
        secs: config.discovery_retry_secs,
        max: config.discovery_retries_max,
    };

    let (machine_id, interface_id) = match tryhard::retry_fn(|| {
        tracing::info!("Trying to register the machine");
        register::run(
            &config.api,
            config.root_ca.clone(),
            config.machine_interface_id,
            &retry,
            &config.tpm_path,
        )
    })
    .retries(retry.max)
    .custom_backoff(|_attempt, error: &CarbideClientError| {
        // we only want to retry if attestation has failed. In all other cases
        // just preserve the old behaviour by breaking from the retry loop
        tracing::error!("Failed to register machine with error {}", error);
        if !error.to_string().contains("Attestation failed") {
            tracing::info!("Not retrying registration as it is not an attestation error");
            RetryPolicy::Break
        } else {
            tracing::info!("Retrying registration again in {} seconds", retry.secs);
            RetryPolicy::Delay(Duration::from_secs(retry.secs))
        }
    })
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

    let machine_interface_id = if let Some(interface_id) = config.machine_interface_id {
        interface_id
    } else if let Some(interface_id) = interface_id {
        interface_id
    } else {
        return Err(eyre::eyre!(
            "machine_interface_id is unknown. Can't continue."
        ));
    };

    Ok((machine_interface_id, machine_id))
}

async fn run_as_service(config: &Options) -> Result<(), eyre::Report> {
    // Implement the logic to run as a service here
    let (machine_interface_id, machine_id) = initial_setup(config).await?;

    // set up a task to check once a day if certs are less than two days from expiry
    let client_cert = config.client_cert.clone();

    let mut next_certs_check_time = get_next_certs_check_datetime()?;

    // Do a one-time publish of MlxDeviceReport data at service
    // start time for now. This will eventually be folded into
    // an Action::MlxDevice feedback loop, but doing some preliminary
    // work for now to get at the data. This was originally part of the
    // common registration client, but I realized that was the wrong
    // place to put it: since this is going to be part of the Action
    // feedback loop, a more accurate place to run this would be after
    // initial_setup (and after registration is complete).
    match mlx_device::create_device_report_request(machine_id) {
        Ok(request) => match mlx_device::publish_mlx_device_report(config, request).await {
            Ok(response) => tracing::info!("recevied PublishMlxDeviceReportResponse: {response:?}"),
            Err(e) => tracing::warn!("failed to publish PublishMlxDeviceReportRequest: {e:?}"),
        },
        Err(e) => tracing::warn!("failed to create PublishMlxDeviceReportRequest: {e:?}"),
    };

    let mut scout_stream_started = false;
    loop {
        if is_time_to_check_certs_expiry(next_certs_check_time) {
            next_certs_check_time = get_next_certs_check_datetime()?;
            tracing::info!("Renewed next certs check time to {}", next_certs_check_time);

            if check_certs_validity(&client_cert)? {
                initial_setup(config).await?;
            }
        }
        let controller_response = match query_api_with_retries(config, &machine_id).await {
            Ok(action) => action,
            Err(e) => {
                report_scout_error(config, None, Some(machine_interface_id), &e).await?;
                rpc_forge::ForgeAgentControlResponse {
                    action: Action::Noop as i32,
                    data: None,
                }
            }
        };
        let action = Action::try_from(controller_response.action)
            .map_err(|err| CarbideClientError::RpcDecodeError(err.to_string()))?;
        match handle_action(
            controller_response,
            &machine_id,
            machine_interface_id,
            config,
        )
        .await
        {
            Ok(_) => tracing::info!("Successfully served {}", action.as_str_name()),
            Err(e) => tracing::info!("Failed to serve {}: Err {}", action.as_str_name(), e),
        };

        // Ensure the first scout API query has run before we establish
        // a Scout stream connection. There's no technical reason requiring
        // this, other than it seemed to make sense to do 1 control
        // request/response action flow before setting up any additional
        // scaffolding.
        if !scout_stream_started {
            scout_stream_started = true;
            stream::start_scout_stream(machine_id, config);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn run_standalone(config: &Options) -> Result<(), eyre::Report> {
    // Implement the logic for standalone mode here
    let subcmd: &Command = match &config.subcmd {
        None => {
            Options::command().print_long_help()?;
            std::process::exit(1);
        }
        Some(s) => match s {
            // The mlx-device subcommand doesn't need to be run with any
            // sort of API integration; it's intended purely for interrogating
            // the state of Mellanox devices on the machine, to see what
            // Carbide will see re: reporting, troubleshooting, etc. Just
            // run the command locally and exit.
            Command::Mlx(mlx) => match &mlx.action {
                // Then match on the specific action (Device or Lockdown)
                MlxAction::Device(mlx_device) => {
                    // The mlx device subcommand doesn't need to be run with any
                    // sort of API integration; it's intended purely for interrogating
                    // the state of Mellanox devices on the machine, to see what
                    // Carbide will see re: reporting, troubleshooting, etc. Just
                    // run the command locally and exit.
                    let device_args = DeviceArgs {
                        action: mlx_device.action.clone(),
                    };
                    handle_mlx_device(device_args).map_err(|e| eyre::eyre!("{e}"))?;
                    return Ok(());
                }
                MlxAction::Lockdown(mlx_lockdown) => {
                    handle_mlx_lockdown(mlx_lockdown.action.clone())
                        .map_err(|e| eyre::eyre!("{e}"))?;
                    return Ok(());
                }
            },
            _ => s,
        },
    };

    let (machine_interface_id, machine_id) = initial_setup(config).await?;

    //TODO Could be better; this for backward compatibility. Refactor required
    let controller_response = match query_api_with_retries(config, &machine_id).await {
        Ok(controller_response) => controller_response,
        Err(e) => {
            report_scout_error(config, None, Some(machine_interface_id), &e).await?;
            ForgeAgentControlResponse {
                action: Action::Noop as i32,
                data: None,
            }
        }
    };
    let action = match subcmd {
        Command::AutoDetect(AutoDetect { .. }) => controller_response,
        Command::Deprovision(_) => ForgeAgentControlResponse {
            action: Action::Reset as i32,
            data: None,
        },
        Command::Discovery(_) => ForgeAgentControlResponse {
            action: Action::Discovery as i32,
            data: None,
        },
        Command::Reset(_) => ForgeAgentControlResponse {
            action: Action::Reset as i32,
            data: None,
        },
        Command::Logerror(_) => ForgeAgentControlResponse {
            action: Action::Logerror as i32,
            data: None,
        },
        Command::MachineValidation(data) => ForgeAgentControlResponse {
            action: Action::MachineValidation as i32,
            data: Some(ForgeAgentControlExtraInfo {
                pair: [
                    KeyValuePair {
                        key: "Context".to_string(),
                        value: data.context.clone(),
                    },
                    KeyValuePair {
                        key: "ValidationId".to_string(),
                        value: data.validataion_id.to_string(),
                    },
                    KeyValuePair {
                        key: "IsEnabled".to_string(),
                        value: "true".to_string(),
                    },
                ]
                .to_vec(),
            }),
        },
        // This will have already been caught above and
        // handled, but we need to have it here to make
        // sure we match everything. Maybe this could
        // log something.
        Command::Mlx(_) => return Ok(()),
    };

    handle_action(action, &machine_id, machine_interface_id, config).await?;
    Ok(())
}

async fn handle_action(
    controller_response: rpc_forge::ForgeAgentControlResponse,
    machine_id: &MachineId,
    machine_interface_id: uuid::Uuid,
    config: &Options,
) -> Result<(), CarbideClientError> {
    let action = Action::try_from(controller_response.action)
        .map_err(|err| CarbideClientError::RpcDecodeError(err.to_string()))?;

    match action {
        Action::Discovery => {
            // This is temporary. All cleanup must be done when API call Reset.
            deprovision::run_no_api().await?;
            let retry = registration::DiscoveryRetry {
                secs: config.discovery_retry_secs,
                max: config.discovery_retries_max,
            };

            register::run(
                &config.api,
                config.root_ca.clone(),
                Some(machine_interface_id),
                &retry,
                &config.tpm_path,
            )
            .await?;

            discovery::completed(config, machine_id).await?;
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
            panic!(
                "Retrieved Retry action, which should be handled internally by query_api_with_retries"
            );
        }
        Action::Measure => {
            initial_setup(config).await.map_err(|e| {
                CarbideClientError::GenericError(format!(
                    "Could not perform attestation at the request of forge agent control: {e}"
                ))
            })?;
        }
        Action::MachineValidation => {
            tracing::info!("Machine validation");
            let mut context = "Discovery".to_string();
            let mut id = "".to_string();
            let mut is_enabled = false;
            let mut machine_validation_filter =
                ::machine_validation::MachineValidationFilter::default();
            for item in controller_response.data.unwrap().pair {
                if item.key == "Context" {
                    context = item.value;
                } else if item.key == "ValidationId" {
                    id = item.value;
                } else if item.key == "IsEnabled" {
                    is_enabled = item.value.parse().unwrap_or(true);
                } else if item.key == "MachineValidationFilter" {
                    machine_validation_filter =
                        serde_json::from_str(&item.value).unwrap_or_default();
                }
            }
            let mut ret: Result<(), CarbideClientError> = Ok(());
            if is_enabled {
                ret = match machine_validation::run(
                    config,
                    machine_id,
                    id.clone(),
                    context,
                    machine_validation_filter,
                )
                .await
                {
                    Ok(_) => {
                        tracing::info!("Machine validation completed");
                        Ok(())
                    }
                    Err(err) => Err(err),
                };
            }
            machine_validation::completed(config, machine_id, id, None).await?;
            return ret;
        }
        Action::MlxAction => {
            handle_mlxreport_action(config, machine_id, controller_response.data).await;
            return Ok(());
        }
    }
    Ok(())
}

// carbide sent us an Action::MlxReport command in response to our
// ForgeAgentControlRequest. Process the MlxReport action, which
// will involve doing configuration actions on our CIN NICs.
// We will send a publish_mlx_report request at the end to reflect
// the config actions we took.
async fn handle_mlxreport_action(
    config: &Options,
    machine_id: &MachineId,
    data: Option<ForgeAgentControlExtraInfo>,
) {
    if data.is_none() {
        tracing::error!("handle_mlxreport_action Did not expect extra data to be empty");
        return;
    }
    let ed = data.unwrap();

    // The Extra data is an array of key value pairs.
    // The key is the pci_name of a DPA NIC.
    // The value is a json encoded DpaCommand.
    // The DpaCommand can be Unlock/Lock, which don't have any other
    // data (currently - may be we will send the lock/unlock key)
    // The DpaCommand can also be ApplyProfile, in which case it
    // will have the profile name.

    let mut report = MlxObservationReport {
        machine_id: Some(*machine_id),
        timestamp: Some(Utc::now().into()),
        observations: Vec::new(),
    };

    for kv in ed.pair {
        let dev_pci_name = kv.key;
        let action = kv.value;

        if dev_pci_name.is_empty() {
            tracing::error!("handle_mlxreport_action dev_pci_name empty");
            continue;
        }

        if action.is_empty() {
            tracing::error!(
                "handle_mlxreport_action action empty for dev: {:#?}",
                dev_pci_name
            );
            continue;
        }

        let dev = match discover_device(&dev_pci_name) {
            Ok(d) => d,
            Err(s) => {
                tracing::error!(
                    "handle_mlxreport_action Error from discover_device::from_str {s} for dev: {:#?}",
                    dev_pci_name
                );
                continue;
            }
        };

        // The action is a structure with an OpCode (like Lock/Unlock/ApplyProfile)
        // and an additional optional string (for ApplyProfile)

        let dpa_cmd: DpaCommand = match serde_json::from_str(&action) {
            Ok(dpc) => dpc,
            Err(e) => {
                tracing::error!(
                    "handle_mlxreport_action Error decodeing DpaCommand {e} for dev: {:#?}",
                    dev_pci_name
                );
                continue;
            }
        };

        match dpa_cmd.op {
            OpCode::Noop => (),
            OpCode::Lock { key } => match mlx_device::lock_device(&dev_pci_name, &key) {
                Ok(()) => {
                    let obs = MlxObservation {
                        device_info: Some(dev.into()),
                        lock_status: Some(LockStatus::Locked.into()),
                        profile_name: None,
                        profile_synced: None,
                    };
                    report.observations.push(obs);
                }
                Err(e) => {
                    tracing::info!(
                        "handle_mlxreport_action Error from lock_device: {e} for dev: {:#?}",
                        dev_pci_name
                    );
                }
            },
            OpCode::ApplyProfile { profile_str } => {
                // XXX TODO XXX
                // Call appropriate mlx routine to apply profile and handle errors
                // XXX TODO XXX
                let obs = MlxObservation {
                    device_info: Some(dev.into()),
                    lock_status: None,
                    profile_name: Some(profile_str),
                    profile_synced: Some(true),
                };
                report.observations.push(obs);
            }
            OpCode::Unlock { key } => match mlx_device::unlock_device(&dev_pci_name, &key) {
                Ok(()) => {
                    let obs = MlxObservation {
                        device_info: Some(dev.into()),
                        lock_status: Some(LockStatus::Unlocked.into()),
                        profile_name: None,
                        profile_synced: None,
                    };
                    report.observations.push(obs);
                }
                Err(e) => {
                    tracing::info!(
                        "handle_mlxreport_action Error from unlock_device: {e} for dev: {:#?}",
                        dev_pci_name
                    );
                }
            },
        };
    }

    let req = PublishMlxObservationReportRequest {
        report: Some(report),
    };

    // Now send the report back to Carbide
    match mlx_device::publish_mlx_observation_report(config, req).await {
        Ok(_resp) => (),
        Err(e) => {
            tracing::error!("Error from publish_mlx_observation_report {e}");
        }
    }
}

// Return the last 1500 bytes of the cloud-init-output.log file as a String
fn get_log_str() -> eyre::Result<String> {
    let mut ret_str = String::new();

    let text = std::fs::read_to_string("/var/log/cloud-init-output.log")?;

    for line in text.lines().rev() {
        let line_str = format!("{line}\n");
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
    machine_id: Option<MachineId>,
    machine_interface_id: Option<uuid::Uuid>,
    error: &impl std::error::Error,
) -> CarbideClientResult<()> {
    let request: tonic::Request<ForgeScoutErrorReport> =
        tonic::Request::new(ForgeScoutErrorReport {
            machine_id,
            machine_interface_id: machine_interface_id.map(|x| x.into()),
            error: format!("{error:#}"), // Alternate representation also prints inner errors
        });

    let mut client = client::create_forge_client(config).await?;
    let _response = client.report_forge_scout_error(request).await?.into_inner();
    Ok(())
}

/// Ask API if we need to do anything after discovery.
async fn query_api(
    config: &Options,
    machine_id: &MachineId,
    action_attempt: u64,
    query_attempt: u64,
) -> CarbideClientResult<rpc_forge::ForgeAgentControlResponse> {
    tracing::info!(
        "Sending ForgeAgentControlRequest (attempt:{}.{})",
        action_attempt,
        query_attempt,
    );
    let query = rpc_forge::ForgeAgentControlRequest {
        machine_id: Some(*machine_id),
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
    Ok(response)
}

async fn query_api_with_retries(
    config: &Options,
    machine_id: &MachineId,
) -> CarbideClientResult<rpc_forge::ForgeAgentControlResponse> {
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
        .fixed_backoff(Duration::from_secs(config.discovery_retry_secs))
        .on_retry(|_attempt, _next_delay, error: &CarbideClientError| {
            // We can't move the error, but CarbideClientError contains some results that are not clonable, so just do the format here
            let error = format!("{error}");
            async move { tracing::info!("ForgeAgentControlRequest failed: {error}") }
        });

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
        let controller_response = tryhard::retry_fn(|| {
            query_attempt += 1;
            query_api(config, machine_id, action_attempt, query_attempt)
        })
        .with_config(retry_config)
        .await?;

        action_attempt += 1;
        let action = Action::try_from(controller_response.action)
            .map_err(|err| CarbideClientError::RpcDecodeError(err.to_string()))?;

        if action != Action::Retry {
            return Ok(controller_response);
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

fn get_next_certs_check_datetime() -> CarbideClientResult<DateTime<Utc>> {
    let Some(next_certs_check_time) = Utc::now().checked_add_days(Days::new(1)) else {
        return Err(CarbideClientError::GenericError(
            "Could not obtain next certs check time".to_string(),
        ));
    };
    Ok(next_certs_check_time)
}

fn is_time_to_check_certs_expiry(next_check_time: DateTime<Utc>) -> bool {
    let now = Utc::now();
    let diff = next_check_time - now;
    if diff < TimeDelta::minutes(2) {
        tracing::info!(
            "Time to check certs expiry: time now is {}, certs check time is {}",
            now,
            next_check_time
        );
        return true;
    }
    false
}

fn check_certs_validity(client_cert_path: &str) -> CarbideClientResult<bool> {
    tracing::info!("Checking if client certs are going to expire soon ...");
    let mut ca_file = File::open(client_cert_path).map_err(CarbideClientError::StdIo)?;

    let mut ca_file_bytes: Vec<u8> = Vec::new();
    ca_file
        .read_to_end(&mut ca_file_bytes)
        .map_err(CarbideClientError::StdIo)?;

    let ca_file_bytes_der = {
        // convert pem to der to normalize
        let res = parse_x509_pem(&ca_file_bytes);
        match res {
            Ok((rem, pem)) => {
                if !rem.is_empty() && (pem.label != *"CERTIFICATE") {
                    return Err(CarbideClientError::GenericError(
                        "PEM certificate validation failed".to_string(),
                    ));
                }

                pem.contents
            }
            _ => {
                return Err(CarbideClientError::GenericError(
                    "Could not parse PEM certificate".to_string(),
                ));
            }
        }
    };

    // create the certificate
    let ca_cert = X509Certificate::from_der(&ca_file_bytes_der)
        .map_err(|e| CarbideClientError::GenericError(format!("Could not parse CA cert: {e}")))?
        .1;

    // if not after timestamp is less than two days away, initiate certs regen
    let not_after = ca_cert.validity.not_after.timestamp();
    if let Some(not_after_datetime) = DateTime::from_timestamp(not_after, 0) {
        let now = Utc::now();
        let diff = not_after_datetime - now;
        if diff < TimeDelta::days(2) {
            tracing::info!(
                "Now timestamp is {}, NotAfter is {}, triggering certs regen",
                now,
                not_after_datetime
            );
            Ok(true)
        } else {
            tracing::info!(
                "Now timestamp is {}, NotAfter is {}, NOT triggering certs regen",
                now,
                not_after_datetime
            );
            Ok(false)
        }
    } else {
        Err(CarbideClientError::GenericError(format!(
            "Could not parse NotAfter timestamp: {not_after}"
        )))
    }
}
