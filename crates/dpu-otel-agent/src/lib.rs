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

use std::sync::Arc;

use ::rpc::forge_tls_client::ForgeClientConfig;
use carbide_host_support::agent_config::AgentConfig;
pub use command_line::{AgentCommand, Options, RunOptions};
use eyre::WrapErr;
use forge_tls::client_config::ClientCert;

mod command_line;

mod main_loop;

pub async fn start(cmdline: command_line::Options) -> eyre::Result<()> {
    let (agent, path) = match cmdline.config_path {
        // normal production case
        None => (AgentConfig::default(), "default".to_string()),
        // development overrides
        Some(config_path) => (
            AgentConfig::load_from(&config_path).wrap_err(format!(
                "Error loading agent configuration from {}",
                config_path.display()
            ))?,
            config_path.display().to_string(),
        ),
    };
    tracing::info!("Using configuration from {path}: {agent:?}");

    let forge_client_config = Arc::new(
        ForgeClientConfig::new(
            agent.forge_system.root_ca.clone(),
            Some(ClientCert {
                cert_path: agent.forge_system.client_cert.clone(),
                key_path: agent.forge_system.client_key.clone(),
            }),
        )
        .use_mgmt_vrf()?,
    );

    match cmdline.cmd {
        None => {
            tracing::error!("Missing cmd. Try `forge-dpu-otel-agent --help`");
        }

        Some(AgentCommand::Run(options)) => {
            main_loop::setup_and_run(forge_client_config, agent, *options)
                .await
                .wrap_err("main_loop error exit")?;
            tracing::info!("Agent exit");
        }
    }
    Ok(())
}
