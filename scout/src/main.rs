/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use cfg::{AutoDetect, Command, Discovery, Options};
use log::LevelFilter;
use once_cell::sync::Lazy;
use rpc::forge as rpc_forge;
use rpc::forge::forge_agent_control_response::Action;
pub use scout::{CarbideClientError, CarbideClientResult};
use tokio::sync::RwLock;

mod cfg;
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
            IN_QEMU_VM.write().await.in_qemu = true; // Not sure. But if above command is not present,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

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

    match config.subcmd {
        Command::Discovery(Discovery { uuid }) | Command::AutoDetect(AutoDetect { uuid }) => {
            let machine_id = register::run(&config.api, uuid).await?;

            match query_api(&config.api, &machine_id).await? {
                Action::Discovery => {
                    //This is temporary. All cleanup must be done when API call Reset.
                    deprovision::run_no_api();

                    discovery::run(&config.api, &machine_id).await?;
                    discovery::completed(&config.api, &machine_id).await?;
                }
                Action::Reset => {
                    deprovision::run(&config.api, &machine_id).await?;
                }
                Action::Rebuild => {
                    unimplemented!("Rebuild not written yet");
                }
                Action::Noop => {}
            }
        }

        Command::Deprovision(d) => {
            let machine_id = register::run(&config.api, d.uuid).await?;
            deprovision::run(&config.api, &machine_id).await?;
        }
    }
    Ok(())
}

/// Ask API if we need to do anything after discovery.
async fn query_api(forge_api: &str, machine_id: &str) -> CarbideClientResult<Action> {
    let query = rpc_forge::ForgeAgentControlRequest {
        machine_id: Some(machine_id.to_string().into()),
    };
    let request = tonic::Request::new(query);
    let mut client = rpc_forge::forge_client::ForgeClient::connect(forge_api.to_string()).await?;
    let response = client.forge_agent_control(request).await?.into_inner();
    let action = Action::try_from(response.action)?;
    Ok(action)
}
