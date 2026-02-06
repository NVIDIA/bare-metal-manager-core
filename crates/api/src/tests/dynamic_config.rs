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
use rpc::forge::forge_server::Forge;
use rpc::forge::{ConfigSetting, SetDynamicConfigRequest};

use crate::setup::parse_carbide_config;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_test_env_with_overrides, get_config,
};

#[crate::sqlx_test]
async fn test_bmc_proxy_setting_config_allowed(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = {
        let mut config = get_config();
        config.site_explorer.allow_changing_bmc_proxy = Some(true);
        create_test_env_with_overrides(db_pool, TestEnvOverrides::with_config(config)).await
    };

    assert!(matches!(
        env.config.site_explorer.allow_changing_bmc_proxy.as_ref(),
        Some(true)
    ));
    assert!(env.config.site_explorer.bmc_proxy.load().is_none());

    env.api
        .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
            setting: ConfigSetting::BmcProxy as i32,
            value: "test-host:1234".to_string(),
            expiry: None,
        }))
        .await?;
    assert_eq!(
        env.config
            .site_explorer
            .bmc_proxy
            .load()
            .clone()
            .as_ref()
            .clone()
            .expect("bmc_proxy should have gotten set")
            .to_string(),
        "test-host:1234"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_bmc_proxy_setting_config_unspecified(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = {
        let mut config = get_config();
        // Leave allow_changing_bmc_proxy unspecified, it should behave as if false
        config.site_explorer.allow_changing_bmc_proxy = None;
        create_test_env_with_overrides(db_pool, TestEnvOverrides::with_config(config)).await
    };

    assert!(env.config.site_explorer.allow_changing_bmc_proxy.is_none());
    assert!(env.config.site_explorer.bmc_proxy.load().is_none());

    match env
        .api
        .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
            setting: ConfigSetting::BmcProxy as i32,
            value: "test-host:1234".to_string(),
            expiry: None,
        }))
        .await
    {
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::PermissionDenied);
        }
        _ => panic!("Setting dynamic config should have failed with a permission_denied"),
    };

    assert!(env.config.site_explorer.bmc_proxy.load().is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_bmc_proxy_setting_config_not_allowed(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = {
        let mut config = get_config();
        config.site_explorer.allow_changing_bmc_proxy = Some(false);
        create_test_env_with_overrides(db_pool, TestEnvOverrides::with_config(config)).await
    };

    assert!(matches!(
        env.config.site_explorer.allow_changing_bmc_proxy.as_ref(),
        Some(false)
    ));

    assert!(env.config.site_explorer.bmc_proxy.load().is_none());

    match env
        .api
        .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
            setting: ConfigSetting::BmcProxy as i32,
            value: "test-host:1234".to_string(),
            expiry: None,
        }))
        .await
    {
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::PermissionDenied);
        }
        _ => panic!("Setting dynamic config should have failed with a permission_denied"),
    };

    assert!(env.config.site_explorer.bmc_proxy.load().is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_bmc_proxy_setting_parsed_config_unspecified(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = {
        // Create a config with allow_changing_bmc_proxy unset, then pass it to parse_carbide_config,
        // then use *that* config, and assert that it defaults to false
        let mut config = get_config();
        // Leave allow_changing_bmc_proxy unspecified, it should behave as if false
        config.site_explorer.allow_changing_bmc_proxy = None;
        config.site_explorer.bmc_proxy = crate::dynamic_settings::bmc_proxy(None);
        config.site_explorer.override_target_ip = None;
        config.site_explorer.override_target_port = None;
        let config_str = toml::to_string(&config)?;
        let parsed_config = parse_carbide_config(config_str, None)?;
        create_test_env_with_overrides(
            db_pool,
            TestEnvOverrides::with_config(parsed_config.as_ref().to_owned()),
        )
        .await
    };

    assert!(env.config.site_explorer.allow_changing_bmc_proxy.is_none());
    assert!(env.api.dynamic_settings.bmc_proxy.load().is_none());

    match env
        .api
        .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
            setting: ConfigSetting::BmcProxy as i32,
            value: "test-host:1234".to_string(),
            expiry: None,
        }))
        .await
    {
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::PermissionDenied);
        }
        _ => panic!("Setting dynamic config should have failed with a permission_denied"),
    };

    assert!(env.api.dynamic_settings.bmc_proxy.load().is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_bmc_proxy_setting_parsed_config_unspecified_with_bmc_proxy_set(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = {
        // Create a config with allow_changing_bmc_proxy unset, but with bmc_proxy set. This should
        // make allow_changing_bmc_proxy to default to true in parse_carbide_config.
        let mut config = get_config();
        // Leave allow_changing_bmc_proxy unspecified, it should behave as if false
        config.site_explorer.allow_changing_bmc_proxy = None;
        config.site_explorer.bmc_proxy =
            crate::dynamic_settings::bmc_proxy(Some("test:1234".parse().unwrap()));
        let config_str = toml::to_string(&config)?;
        println!("{config_str}");
        let parsed_config = parse_carbide_config(config_str, None)?;
        create_test_env_with_overrides(
            db_pool,
            TestEnvOverrides::with_config(parsed_config.as_ref().to_owned()),
        )
        .await
    };

    assert!(matches!(
        env.config.site_explorer.allow_changing_bmc_proxy.as_ref(),
        Some(true),
    ));

    assert_eq!(
        env.api
            .dynamic_settings
            .bmc_proxy
            .load()
            .clone()
            .as_ref()
            .clone(),
        Some("test:1234".parse().unwrap())
    );

    env.api
        .set_dynamic_config(tonic::Request::new(SetDynamicConfigRequest {
            setting: ConfigSetting::BmcProxy as i32,
            value: "other-host:5678".to_string(),
            expiry: None,
        }))
        .await
        .unwrap();

    assert_eq!(
        env.api
            .dynamic_settings
            .bmc_proxy
            .load()
            .clone()
            .as_ref()
            .clone(),
        Some("other-host:5678".parse().unwrap())
    );

    Ok(())
}
