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

use model::firmware::FirmwareComponentType;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    HostFirmwareArtifact, HostFirmwareComponentConfigResponse, HostFirmwareComponentType,
    HostFirmwareVersionConfig, UpsertHostFirmwareComponentConfig, UpsertHostFirmwareConfigRequest,
};
use tonic::{Code, Request};

use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test]
async fn upsert_host_firmware_config_creates_and_merges_versions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    env.api
        .upsert_host_firmware_config(Request::new(upsert_request(
            vec![component_config(
                HostFirmwareComponentType::Cx7,
                vec![version_config_with_preingestion_exclusive_config(
                    "28.47.2682",
                    true,
                    Some(true),
                )],
                Some("28.48.1000"),
            )],
            vec![HostFirmwareComponentType::Cx7],
            Some(true),
        )))
        .await?;

    let response = env
        .api
        .upsert_host_firmware_config(Request::new(upsert_request(
            vec![component_config(
                HostFirmwareComponentType::Cx7,
                vec![version_config("28.48.1111", true)],
                None,
            )],
            Vec::new(),
            None,
        )))
        .await?
        .into_inner();

    assert!(response.explicit_start_needed);
    assert_eq!(
        response.ordering,
        vec![HostFirmwareComponentType::Cx7 as i32]
    );

    let cx7 = response_component(&response.components, HostFirmwareComponentType::Cx7);
    assert_eq!(
        cx7.preingest_upgrade_when_below.as_deref(),
        Some("28.48.1000")
    );
    assert_eq!(
        firmware_defaults(cx7),
        vec![("28.47.2682", false), ("28.48.1111", true)]
    );
    assert_eq!(
        firmware_preingestion_exclusive_configs(cx7),
        vec![("28.47.2682", Some(true)), ("28.48.1111", Some(false))]
    );

    let mut txn = env.pool.begin().await?;
    let stored = db::host_firmware_config::get(&mut txn, "Nvidia", "dgxh100")
        .await?
        .expect("stored host firmware config")
        .into_config();
    txn.commit().await?;

    assert_eq!(stored.ordering, vec![FirmwareComponentType::Cx7]);
    assert!(stored.explicit_start_needed);
    let stored_cx7 = stored
        .components
        .get(&FirmwareComponentType::Cx7)
        .expect("stored cx7 component");
    assert_eq!(
        stored_cx7.preingest_upgrade_when_below.as_deref(),
        Some("28.48.1000")
    );
    assert_eq!(
        stored_cx7
            .known_firmware
            .iter()
            .map(|firmware| {
                (
                    firmware.version.as_str(),
                    firmware.default,
                    firmware.preingestion_exclusive_config,
                )
            })
            .collect::<Vec<_>>(),
        vec![("28.47.2682", false, true), ("28.48.1111", true, false)]
    );

    Ok(())
}

#[crate::sqlx_test]
async fn upsert_host_firmware_config_rejects_create_without_ordering(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let error = env
        .api
        .upsert_host_firmware_config(Request::new(upsert_request(
            vec![component_config(
                HostFirmwareComponentType::Cx7,
                vec![version_config("28.47.2682", true)],
                None,
            )],
            Vec::new(),
            Some(false),
        )))
        .await
        .expect_err("create without ordering should fail");

    assert_eq!(error.code(), Code::InvalidArgument);

    Ok(())
}

#[crate::sqlx_test]
async fn upsert_host_firmware_config_rejects_added_component_without_ordering_update(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    env.api
        .upsert_host_firmware_config(Request::new(upsert_request(
            vec![component_config(
                HostFirmwareComponentType::Cx7,
                vec![version_config("28.47.2682", true)],
                None,
            )],
            vec![HostFirmwareComponentType::Cx7],
            Some(false),
        )))
        .await?;

    let error = env
        .api
        .upsert_host_firmware_config(Request::new(upsert_request(
            vec![component_config(
                HostFirmwareComponentType::Uefi,
                vec![version_config("96.00.5E.00.01", true)],
                None,
            )],
            Vec::new(),
            None,
        )))
        .await
        .expect_err("adding component without ordering update should fail");

    assert_eq!(error.code(), Code::InvalidArgument);

    let mut txn = env.pool.begin().await?;
    let stored = db::host_firmware_config::get(&mut txn, "Nvidia", "DGXH100")
        .await?
        .expect("stored host firmware config")
        .into_config();
    txn.commit().await?;

    assert_eq!(stored.ordering, vec![FirmwareComponentType::Cx7]);
    assert!(stored.components.contains_key(&FirmwareComponentType::Cx7));
    assert!(!stored.components.contains_key(&FirmwareComponentType::Uefi));

    Ok(())
}

fn upsert_request(
    components: Vec<UpsertHostFirmwareComponentConfig>,
    ordering: Vec<HostFirmwareComponentType>,
    explicit_start_needed: Option<bool>,
) -> UpsertHostFirmwareConfigRequest {
    UpsertHostFirmwareConfigRequest {
        vendor: "Nvidia".to_string(),
        model: "DGXH100".to_string(),
        components,
        explicit_start_needed,
        ordering: ordering
            .into_iter()
            .map(|component_type| component_type as i32)
            .collect(),
    }
}

fn component_config(
    component_type: HostFirmwareComponentType,
    firmware: Vec<HostFirmwareVersionConfig>,
    preingest_upgrade_when_below: Option<&str>,
) -> UpsertHostFirmwareComponentConfig {
    UpsertHostFirmwareComponentConfig {
        r#type: component_type as i32,
        firmware,
        preingest_upgrade_when_below: preingest_upgrade_when_below.map(str::to_string),
    }
}

fn version_config(version: &str, default: bool) -> HostFirmwareVersionConfig {
    version_config_with_preingestion_exclusive_config(version, default, None)
}

fn version_config_with_preingestion_exclusive_config(
    version: &str,
    default: bool,
    preingestion_exclusive_config: Option<bool>,
) -> HostFirmwareVersionConfig {
    HostFirmwareVersionConfig {
        version: version.to_string(),
        default,
        artifacts: vec![HostFirmwareArtifact {
            url: format!("https://firmware.example.invalid/{version}/fw.bin"),
            sha256: None,
        }],
        install_only_specified: false,
        power_drains_needed: None,
        pre_update_resets: false,
        preingestion_exclusive_config,
    }
}

fn response_component(
    components: &[HostFirmwareComponentConfigResponse],
    component_type: HostFirmwareComponentType,
) -> &HostFirmwareComponentConfigResponse {
    components
        .iter()
        .find(|component| component.r#type == component_type as i32)
        .expect("response component")
}

fn firmware_defaults(component: &HostFirmwareComponentConfigResponse) -> Vec<(&str, bool)> {
    let mut versions = component
        .firmware
        .iter()
        .map(|firmware| (firmware.version.as_str(), firmware.default))
        .collect::<Vec<_>>();
    versions.sort_by_key(|(version, _)| *version);
    versions
}

fn firmware_preingestion_exclusive_configs(
    component: &HostFirmwareComponentConfigResponse,
) -> Vec<(&str, Option<bool>)> {
    let mut versions = component
        .firmware
        .iter()
        .map(|firmware| {
            (
                firmware.version.as_str(),
                firmware.preingestion_exclusive_config,
            )
        })
        .collect::<Vec<_>>();
    versions.sort_by_key(|(version, _)| *version);
    versions
}
