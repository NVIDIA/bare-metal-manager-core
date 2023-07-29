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
use std::collections::HashMap;
use std::net::SocketAddr;

use carbide::cfg::{AuthConfig, CarbideConfig, TlsConfig};
use carbide::resource_pool::{Range, ResourcePoolDef, ResourcePoolType};

use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter::EnvFilter, fmt::TestWriter, prelude::*, util::SubscriberInitExt};

pub async fn start(
    addr: SocketAddr,
    root_dir: String,
    db_url: String,
    vault_token: String,
) -> eyre::Result<()> {
    let carbide_config = CarbideConfig {
        listen: addr,
        metrics_endpoint: Some("127.0.0.1:1080".parse().unwrap()),
        otlp_endpoint: None,
        database_url: db_url,
        ib_fabric_manager: None,
        ib_fabric_manager_token: None,
        rapid_iterations: true,
        asn: 65535,
        dhcp_servers: vec![],
        route_servers: vec![],
        tls: Some(TlsConfig {
            identity_pemfile_path: format!("{root_dir}/dev/certs/server_identity.pem"),
            identity_keyfile_path: format!("{root_dir}/dev/certs/server_identity.key"),
            root_cafile_path: format!(
                "{root_dir}/dev/certs/forge_developer_local_only_root_cert_pem"
            ),
            admin_root_cafile_path: "nothing_will_read_from_this_during_integration_tests"
                .to_string(),
        }),
        auth: Some(AuthConfig {
            permissive_mode: true,
            casbin_policy_file: format!("{root_dir}/api/casbin-policy.csv").into(),
        }),
        pools: Some(HashMap::from([
            (
                "lo-ip".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Ipv4,
                    prefix: Some("10.180.62.1/26".to_string()),
                    ranges: vec![],
                },
            ),
            (
                "vlan-id".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "100".to_string(),
                        end: "501".to_string(),
                    }],
                },
            ),
            (
                "vni".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "1024500".to_string(),
                        end: "1024550".to_string(),
                    }],
                },
            ),
            (
                "vpc-vni".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "2024500".to_string(),
                        end: "2024550".to_string(),
                    }],
                },
            ),
            (
                "pkey".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "1".to_string(),
                        end: "10".to_string(),
                    }],
                },
            ),
        ])),
    };

    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_KV_MOUNT_LOCATION", "secret");
    std::env::set_var("VAULT_PKI_MOUNT_LOCATION", "forgeca");
    std::env::set_var("VAULT_PKI_ROLE_NAME", "forge-cluster");
    std::env::set_var("VAULT_TOKEN", vault_token);

    let carbide_config_str = toml::to_string(&carbide_config).unwrap();
    carbide::run(0, carbide_config_str, None, Some(test_logging_subscriber())).await
}

pub fn test_logging_subscriber() -> impl SubscriberInitExt {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("sqlx=warn".parse().unwrap())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    // Note: `TestWriter` is required to use the standard behavior of Rust unit tests:
    // - Successful tests won't show output unless forced by the `--nocapture` CLI argument
    // - Failing tests will have their output printed
    Box::new(
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::Layer::default()
                    .compact()
                    .with_writer(TestWriter::new),
            )
            .with(env_filter),
    )
}
