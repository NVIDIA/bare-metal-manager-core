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
#[command(after_long_help = "\
EXAMPLES:

Queue firmware on NVLink switches from a target version:
    $ nico-admin-cli component-manager update-firmware switch \
    --switch-id 12345678-1234-5678-90ab-cdef01234567 --target-version fw-1.2.3

Update only specific switch components, forcing the update:
    $ nico-admin-cli component-manager update-firmware switch \
    --switch-id 12345678-1234-5678-90ab-cdef01234567 --component bmc,bios --force-update \
    --target-version fw-1.2.3

Queue firmware on compute trays from an RMS SOT JSON file:
    $ nico-admin-cli component-manager update-firmware compute-tray \
    --machine-id 12345678-1234-5678-90ab-cdef01234567 --sot-json-file ./sot.json \
    --access-token mytoken

Queue firmware on power shelves:
    $ nico-admin-cli component-manager update-firmware power-shelf \
    --power-shelf-id 12345678-1234-5678-90ab-cdef01234567 --target-version fw-1.2.3

Queue firmware on all eligible devices in a rack:
    $ nico-admin-cli component-manager update-firmware rack \
    --rack-id 12345678-1234-5678-90ab-cdef01234567 --target-version fw-1.2.3

")]
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
        help = "SOT JSON file for RMS ApplyFirmwareObject"
    )]
    pub sot_json_file: Option<PathBuf>,

    #[clap(
        long = "access-token",
        help = "Artifact access token for RMS SOT JSON downloads; omit or pass empty for NOAUTH"
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
            let token = access_token.and_then(|token| {
                if token.trim().is_empty() {
                    None
                } else {
                    Some(token)
                }
            });

            let config_json = std::fs::read_to_string(sot_json_file)?;
            serde_json::from_str::<serde_json::Value>(&config_json)?;
            Ok((config_json, token))
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

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

    // A firmware source resolves to its (target_version, access_token) pair:
    // a legacy --target-version passes through verbatim with no token, while a
    // SOT JSON file resolves to the file's contents paired with the token --
    // an empty token collapsing to None.
    #[test]
    fn firmware_source_resolves_target_version_and_token() {
        let sot_token = temp_sot_file(r#"{"Id":"fw-object"}"#);
        let sot_no_token = temp_sot_file(r#"{"Id":"fw-object"}"#);
        let sot_empty_token = temp_sot_file(r#"{"Id":"fw-object"}"#);

        scenarios!(
            run = |source| resolve_firmware_source(source).map_err(drop);
            "legacy --target-version passes through with no token" {
                FirmwareSourceArgs {
                    target_version: Some("fw-1.0".to_string()),
                    sot_json_file: None,
                    access_token: None,
                } => Yields(("fw-1.0".to_string(), None)),
            }

            "SOT JSON file resolves to its contents and the access token" {
                FirmwareSourceArgs {
                    target_version: None,
                    sot_json_file: Some(sot_token.clone()),
                    access_token: Some("token".to_string()),
                } => Yields((
                    r#"{"Id":"fw-object"}"#.to_string(),
                    Some("token".to_string()),
                )),
            }

            "SOT JSON file resolves without an access token" {
                FirmwareSourceArgs {
                    target_version: None,
                    sot_json_file: Some(sot_no_token.clone()),
                    access_token: None,
                } => Yields((r#"{"Id":"fw-object"}"#.to_string(), None)),
            }

            "an empty access token collapses to None" {
                FirmwareSourceArgs {
                    target_version: None,
                    sot_json_file: Some(sot_empty_token.clone()),
                    access_token: Some(String::new()),
                } => Yields((r#"{"Id":"fw-object"}"#.to_string(), None)),
            }
        );

        let _ = std::fs::remove_file(sot_token);
        let _ = std::fs::remove_file(sot_no_token);
        let _ = std::fs::remove_file(sot_empty_token);
    }

    // A firmware source is rejected when its parts are incoherent: an access
    // token without a SOT JSON file has nothing to authenticate, and a SOT JSON
    // file whose contents aren't valid JSON can't be parsed. (CarbideCliError is
    // not PartialEq, so these assert only that resolution fails.)
    #[test]
    fn firmware_source_rejects_incoherent_inputs() {
        let invalid_json = temp_sot_file("not-json");

        scenarios!(
            run = |source| resolve_firmware_source(source).map_err(drop);
            "access token without a SOT JSON file" {
                FirmwareSourceArgs {
                    target_version: Some("fw-1.0".to_string()),
                    sot_json_file: None,
                    access_token: Some("token".to_string()),
                } => Fails,
            }

            "SOT JSON file whose contents are not valid JSON" {
                FirmwareSourceArgs {
                    target_version: None,
                    sot_json_file: Some(invalid_json.clone()),
                    access_token: Some("token".to_string()),
                } => Fails,
            }
        );

        let _ = std::fs::remove_file(invalid_json);
    }
}
