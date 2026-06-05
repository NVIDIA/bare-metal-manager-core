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

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};

use crate::component_manager::common::{
    ComputeTrayComponentArg, MachineTargetArgs, NvSwitchComponentArg, PowerShelfComponentArg,
    PowerShelfTargetArgs, RackTargetArgs, SwitchTargetArgs,
};
use crate::errors::{CarbideCliError, CarbideCliResult};

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub target: Target,
}

#[derive(Subcommand, Debug)]
pub enum Target {
    #[clap(about = "Queue firmware on NVLink switches")]
    Switch(SwitchArgs),

    #[clap(about = "Queue firmware on power shelves")]
    PowerShelf(PowerShelfArgs),

    #[clap(about = "Queue firmware on compute trays")]
    ComputeTray(ComputeTrayArgs),

    #[clap(about = "Queue firmware on all eligible devices in racks")]
    Rack(RackArgs),
}

#[derive(ClapArgs, Debug)]
pub struct SwitchArgs {
    #[clap(flatten)]
    pub ids: SwitchTargetArgs,

    #[clap(flatten)]
    pub firmware_source: FirmwareSourceArgs,

    #[clap(long = "force-update", help = "Force firmware update when supported")]
    pub force_update: bool,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "NVLink switch components to update; omit to update all supported components"
    )]
    pub components: Vec<NvSwitchComponentArg>,

    #[clap(
        long = "bypass-state-controller",
        help = "Bypass the state controller and dispatch directly to the component backend"
    )]
    pub bypass_state_controller: bool,
}

#[derive(ClapArgs, Debug)]
pub struct PowerShelfArgs {
    #[clap(flatten)]
    pub ids: PowerShelfTargetArgs,

    #[clap(long = "target-version", help = "Firmware target version")]
    pub target_version: String,

    #[clap(long = "force-update", help = "Force firmware update when supported")]
    pub force_update: bool,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "Power shelf components to update; omit to update all supported components"
    )]
    pub components: Vec<PowerShelfComponentArg>,

    #[clap(
        long = "bypass-state-controller",
        help = "Bypass the state controller and dispatch directly to the component backend"
    )]
    pub bypass_state_controller: bool,
}

#[derive(ClapArgs, Debug)]
pub struct ComputeTrayArgs {
    #[clap(flatten)]
    pub ids: MachineTargetArgs,

    #[clap(flatten)]
    pub firmware_source: FirmwareSourceArgs,

    #[clap(long = "force-update", help = "Force firmware update when supported")]
    pub force_update: bool,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "Compute tray components to update; omit to update all supported components"
    )]
    pub components: Vec<ComputeTrayComponentArg>,

    #[clap(
        long = "bypass-state-controller",
        help = "Bypass the state controller and dispatch directly to the component backend"
    )]
    pub bypass_state_controller: bool,
}

#[derive(ClapArgs, Debug)]
pub struct RackArgs {
    #[clap(flatten)]
    pub ids: RackTargetArgs,

    #[clap(flatten)]
    pub firmware_source: FirmwareSourceArgs,

    #[clap(long = "force-update", help = "Force firmware update when supported")]
    pub force_update: bool,
}

#[derive(ClapArgs, Debug)]
pub struct FirmwareSourceArgs {
    #[clap(
        long = "target-version",
        help = "Firmware target version for legacy direct-update paths"
    )]
    pub target_version: Option<String>,

    #[clap(
        long = "sot-json-file",
        value_name = "PATH",
        help = "SOT JSON file for RMS ApplyFirmwareObjectFromJSON"
    )]
    pub sot_json_file: Option<PathBuf>,

    #[clap(
        long = "access-token",
        help = "Artifact access token; required with --sot-json-file"
    )]
    pub access_token: Option<String>,
}

fn resolve_firmware_source(
    source: FirmwareSourceArgs,
) -> CarbideCliResult<(String, Option<String>)> {
    match (
        source.target_version,
        source.sot_json_file,
        source.access_token,
    ) {
        (Some(_), Some(_), _) => Err(CarbideCliError::ChooseOneError(
            "--target-version",
            "--sot-json-file",
        )),
        (None, None, _) => Err(CarbideCliError::RequireOneError(
            "--target-version",
            "--sot-json-file",
        )),
        (Some(_), None, Some(_)) => Err(CarbideCliError::GenericError(
            "--access-token requires --sot-json-file".to_string(),
        )),
        (Some(target_version), None, None) => {
            if target_version.trim().is_empty() {
                Err(CarbideCliError::GenericError(
                    "--target-version must not be empty".to_string(),
                ))
            } else {
                Ok((target_version, None))
            }
        }
        (None, Some(sot_json_file), access_token) => {
            let token = access_token.ok_or_else(|| {
                CarbideCliError::GenericError(
                    "--access-token is required with --sot-json-file".to_string(),
                )
            })?;
            if token.trim().is_empty() {
                return Err(CarbideCliError::GenericError(
                    "--access-token must not be empty".to_string(),
                ));
            }

            let config_json = std::fs::read_to_string(sot_json_file)?;
            serde_json::from_str::<serde_json::Value>(&config_json)?;
            Ok((config_json, Some(token)))
        }
    }
}

impl TryFrom<Args> for rpc::forge::UpdateComponentFirmwareRequest {
    type Error = CarbideCliError;

    fn try_from(args: Args) -> CarbideCliResult<Self> {
        match args.target {
            Target::Switch(target) => {
                let (target_version, access_token) =
                    resolve_firmware_source(target.firmware_source)?;
                Ok(Self {
                    target_version,
                    access_token,
                    force_update: target.force_update,
                    bypass_state_controller: target.bypass_state_controller,
                    target: Some(
                        rpc::forge::update_component_firmware_request::Target::Switches(
                            rpc::forge::UpdateSwitchFirmwareTarget {
                                switch_ids: Some(target.ids.into()),
                                components: target
                                    .components
                                    .into_iter()
                                    .map(|component| {
                                        rpc::forge::NvSwitchComponent::from(component) as i32
                                    })
                                    .collect(),
                            },
                        ),
                    ),
                })
            }
            Target::PowerShelf(target) => Ok(Self {
                target_version: target.target_version,
                access_token: None,
                force_update: target.force_update,
                bypass_state_controller: target.bypass_state_controller,
                target: Some(
                    rpc::forge::update_component_firmware_request::Target::PowerShelves(
                        rpc::forge::UpdatePowerShelfFirmwareTarget {
                            power_shelf_ids: Some(target.ids.into()),
                            components: target
                                .components
                                .into_iter()
                                .map(|component| {
                                    rpc::forge::PowerShelfComponent::from(component) as i32
                                })
                                .collect(),
                        },
                    ),
                ),
            }),
            Target::ComputeTray(target) => {
                let (target_version, access_token) =
                    resolve_firmware_source(target.firmware_source)?;
                Ok(Self {
                    target_version,
                    access_token,
                    force_update: target.force_update,
                    bypass_state_controller: target.bypass_state_controller,
                    target: Some(
                        rpc::forge::update_component_firmware_request::Target::ComputeTrays(
                            rpc::forge::UpdateComputeTrayFirmwareTarget {
                                machine_ids: Some(target.ids.into()),
                                components: target
                                    .components
                                    .into_iter()
                                    .map(|component| {
                                        rpc::forge::ComputeTrayComponent::from(component) as i32
                                    })
                                    .collect(),
                            },
                        ),
                    ),
                })
            }
            Target::Rack(target) => {
                let (target_version, access_token) =
                    resolve_firmware_source(target.firmware_source)?;
                Ok(Self {
                    target_version,
                    access_token,
                    force_update: target.force_update,
                    bypass_state_controller: false,
                    target: Some(
                        rpc::forge::update_component_firmware_request::Target::Racks(
                            rpc::forge::UpdateFirmwareObjectTarget {
                                rack_ids: Some(target.ids.into()),
                            },
                        ),
                    ),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_sot_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bmm-sot-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ));
        std::fs::write(&path, contents).expect("write test SOT JSON");
        path
    }

    #[test]
    fn target_version_source_uses_legacy_version() {
        let (target_version, access_token) = resolve_firmware_source(FirmwareSourceArgs {
            target_version: Some("fw-1.0".to_string()),
            sot_json_file: None,
            access_token: None,
        })
        .expect("legacy source should resolve");

        assert_eq!(target_version, "fw-1.0");
        assert_eq!(access_token, None);
    }

    #[test]
    fn sot_json_source_reads_file_and_sets_access_token() {
        let path = temp_sot_file(r#"{"Id":"fw-object"}"#);

        let (target_version, access_token) = resolve_firmware_source(FirmwareSourceArgs {
            target_version: None,
            sot_json_file: Some(path.clone()),
            access_token: Some("token".to_string()),
        })
        .expect("SOT source should resolve");

        assert_eq!(target_version, r#"{"Id":"fw-object"}"#);
        assert_eq!(access_token.as_deref(), Some("token"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn access_token_without_sot_json_file_is_rejected() {
        let err = resolve_firmware_source(FirmwareSourceArgs {
            target_version: Some("fw-1.0".to_string()),
            sot_json_file: None,
            access_token: Some("token".to_string()),
        })
        .expect_err("access token without SOT JSON should fail");

        assert!(err.to_string().contains("--access-token requires"));
    }

    #[test]
    fn invalid_sot_json_file_is_rejected() {
        let path = temp_sot_file("not-json");

        let err = resolve_firmware_source(FirmwareSourceArgs {
            target_version: None,
            sot_json_file: Some(path.clone()),
            access_token: Some("token".to_string()),
        })
        .expect_err("invalid SOT JSON should fail");

        assert!(matches!(err, CarbideCliError::JsonError(_)));
        let _ = std::fs::remove_file(path);
    }
}
