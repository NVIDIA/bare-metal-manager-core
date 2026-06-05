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

use ::rpc::forge as rpc;

use super::args::MaintenanceOptions;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

fn resolve_firmware_upgrade_source(
    args: &MaintenanceOptions,
) -> CarbideCliResult<(String, Option<String>)> {
    let explicit_firmware_upgrade = args.activities.as_ref().is_some_and(|activities| {
        activities
            .iter()
            .any(|activity| activity == "firmware-upgrade")
    });
    let explicit_nvos_update = args
        .activities
        .as_ref()
        .is_some_and(|activities| activities.iter().any(|activity| activity == "nvos-update"));
    let requires_firmware_object_json = explicit_firmware_upgrade || explicit_nvos_update;

    if args.firmware_version.is_some() && args.sot_json_file.is_some() {
        return Err(CarbideCliError::ChooseOneError(
            "--firmware-version",
            "--sot-json-file",
        ));
    }

    let firmware_version = if let Some(path) = args.sot_json_file.as_ref() {
        let config_json = std::fs::read_to_string(path)?;
        serde_json::from_str::<serde_json::Value>(&config_json)?;
        config_json
    } else {
        args.firmware_version.clone().unwrap_or_default()
    };

    let access_token = args.access_token.as_ref().and_then(|token| {
        if token.trim().is_empty() {
            None
        } else {
            Some(token.clone())
        }
    });

    if args.sot_json_file.is_some() && access_token.is_none() {
        return Err(CarbideCliError::GenericError(
            "--access-token is required with --sot-json-file".to_string(),
        ));
    }
    if requires_firmware_object_json && firmware_version.trim().is_empty() {
        return Err(CarbideCliError::GenericError(
            "--activities firmware-upgrade/nvos-update requires SOT JSON from --sot-json-file or --firmware-version"
                .to_string(),
        ));
    }
    if requires_firmware_object_json && access_token.is_none() {
        return Err(CarbideCliError::GenericError(
            "--activities firmware-upgrade/nvos-update requires --access-token".to_string(),
        ));
    }
    if !requires_firmware_object_json && args.sot_json_file.is_some() {
        return Err(CarbideCliError::GenericError(
            "--sot-json-file requires --activities firmware-upgrade or nvos-update".to_string(),
        ));
    }
    if !requires_firmware_object_json && args.firmware_version.is_some() {
        return Err(CarbideCliError::GenericError(
            "--firmware-version requires --activities firmware-upgrade or nvos-update".to_string(),
        ));
    }
    if !requires_firmware_object_json && args.access_token.is_some() {
        return Err(CarbideCliError::GenericError(
            "--access-token requires --activities firmware-upgrade or nvos-update".to_string(),
        ));
    }
    if access_token.is_some() && args.firmware_version.is_some() {
        serde_json::from_str::<serde_json::Value>(&firmware_version)?;
    }

    Ok((firmware_version, access_token))
}

pub async fn on_demand_rack_maintenance(
    api_client: &ApiClient,
    args: MaintenanceOptions,
) -> CarbideCliResult<()> {
    use rpc::maintenance_activity_config::Activity as ProtoActivity;

    let (firmware_version, access_token) = resolve_firmware_upgrade_source(&args)?;
    let components = args.components.unwrap_or_default();
    let force_update = args.force_update;

    let activities: Vec<rpc::MaintenanceActivityConfig> = args
        .activities
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let activity = match s.as_str() {
                "firmware-upgrade" => {
                    Ok(ProtoActivity::FirmwareUpgrade(rpc::FirmwareUpgradeActivity {
                        firmware_version: firmware_version.clone(),
                        components: components.clone(),
                        access_token: access_token.clone(),
                        force_update,
                    }))
                }
                "nvos-update" => Ok(ProtoActivity::NvosUpdate(rpc::NvosUpdateActivity {
                    config_json: firmware_version.clone(),
                    access_token: access_token.clone(),
                })),
                "configure-nmx-cluster" => Ok(ProtoActivity::ConfigureNmxCluster(
                    rpc::ConfigureNmxClusterActivity {},
                )),
                "power-sequence" => Ok(ProtoActivity::PowerSequence(
                    rpc::PowerSequenceActivity {},
                )),
                other => Err(eyre::eyre!(
                    "Unknown activity '{}'. Valid values: firmware-upgrade, nvos-update, configure-nmx-cluster, power-sequence",
                    other
                )),
            }?;
            Ok::<_, eyre::Report>(rpc::MaintenanceActivityConfig {
                activity: Some(activity),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    api_client
        .on_demand_rack_maintenance(
            args.rack,
            args.machine_ids.unwrap_or_default(),
            args.switch_ids.unwrap_or_default(),
            args.power_shelf_ids.unwrap_or_default(),
            activities,
        )
        .await?;
    println!("On-demand rack maintenance scheduled successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use carbide_uuid::rack::RackId;

    use super::*;

    fn options() -> MaintenanceOptions {
        MaintenanceOptions {
            rack: RackId::new("rack-test"),
            machine_ids: None,
            switch_ids: None,
            power_shelf_ids: None,
            activities: None,
            firmware_version: None,
            sot_json_file: None,
            access_token: None,
            force_update: false,
            components: None,
        }
    }

    #[test]
    fn firmware_upgrade_requires_sot_json() {
        let args = MaintenanceOptions {
            activities: Some(vec!["firmware-upgrade".to_string()]),
            access_token: Some("token".to_string()),
            ..options()
        };

        let err = resolve_firmware_upgrade_source(&args).unwrap_err();

        assert!(err.to_string().contains("requires SOT JSON"));
    }

    #[test]
    fn firmware_upgrade_requires_access_token() {
        let args = MaintenanceOptions {
            activities: Some(vec!["firmware-upgrade".to_string()]),
            firmware_version: Some(r#"{"Id":"fw"}"#.to_string()),
            ..options()
        };

        let err = resolve_firmware_upgrade_source(&args).unwrap_err();

        assert!(err.to_string().contains("requires --access-token"));
    }

    #[test]
    fn firmware_upgrade_rejects_invalid_inline_json() {
        let args = MaintenanceOptions {
            activities: Some(vec!["firmware-upgrade".to_string()]),
            firmware_version: Some("not-json".to_string()),
            access_token: Some("token".to_string()),
            ..options()
        };

        assert!(resolve_firmware_upgrade_source(&args).is_err());
    }

    #[test]
    fn firmware_source_requires_firmware_upgrade_activity() {
        let args = MaintenanceOptions {
            firmware_version: Some(r#"{"Id":"fw"}"#.to_string()),
            ..options()
        };

        let err = resolve_firmware_upgrade_source(&args).unwrap_err();

        assert!(
            err.to_string().contains(
                "--firmware-version requires --activities firmware-upgrade or nvos-update"
            )
        );
    }

    #[test]
    fn access_token_requires_firmware_upgrade_activity() {
        let args = MaintenanceOptions {
            access_token: Some("token".to_string()),
            ..options()
        };

        let err = resolve_firmware_upgrade_source(&args).unwrap_err();

        assert!(
            err.to_string()
                .contains("--access-token requires --activities firmware-upgrade or nvos-update")
        );
    }
}
