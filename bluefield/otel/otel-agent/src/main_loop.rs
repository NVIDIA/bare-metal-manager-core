/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::{Duration, Instant};

use ::rpc::forge_tls_client;
use forge_certs::cert_renewal::ClientCertRenewer;
use forge_host_support::agent_config::AgentConfig;
use forge_systemd::systemd;
use forge_tls::client_config::ClientCert;
use humantime::format_duration as dt;
use tokio::signal::unix::{signal, SignalKind};

use crate::command_line;

pub async fn setup_and_run(
    forge_client_config: forge_tls_client::ForgeClientConfig,
    agent_config: AgentConfig,
    options: command_line::RunOptions,
) -> eyre::Result<()> {
    systemd::notify_start().await?;
    tracing::info!(
        options = ?options,
        "Started forge-dpu-otel-agent"
    );

    let forge_api_server = agent_config.forge_system.api_server.clone();
    // Setup client certificate renewal
    let client_cert_renewer =
        ClientCertRenewer::new(forge_api_server.clone(), forge_client_config.clone());

    let main_loop = MainLoop {
        agent_config,
        client_cert_renewer,
        forge_client_config,
        started_at: Instant::now(),
    };

    main_loop.run().await
}

struct MainLoop {
    agent_config: AgentConfig,
    client_cert_renewer: ClientCertRenewer,
    forge_client_config: forge_tls_client::ForgeClientConfig,
    started_at: Instant,
}

struct IterationResult {
    stop_agent: bool,
    loop_period: Duration,
}

impl MainLoop {
    /// Runs the MainLoop in endless mode
    async fn run(mut self) -> Result<(), eyre::Report> {
        let mut term_signal = signal(SignalKind::terminate())?;
        let mut hup_signal = signal(SignalKind::hangup())?;

        let certs = ClientCert {
            cert_path: self.agent_config.forge_system.client_cert.clone(),
            key_path: self.agent_config.forge_system.client_key.clone(),
        };

        loop {
            let result = self.run_single_iteration(&certs).await?;
            if result.stop_agent {
                return Ok(());
            }

            tokio::select! {
                biased;
                _ = term_signal.recv() => {
                    systemd::notify_stop().await?;
                    tracing::info!("TERM signal received, clean exit");
                    return Ok(());
                }
                _ = hup_signal.recv() => {
                    tracing::info!("Hangup received, timer reset");
                    self.client_cert_renewer.renew_on_next_check();
                }
                _ = tokio::time::sleep(result.loop_period) => {}
            }
        }
    }

    /// Runs a single iteration of the main loop
    async fn run_single_iteration(
        &mut self,
        certs: &ClientCert,
    ) -> Result<IterationResult, eyre::Report> {
        let loop_start = Instant::now();

        if let Err(err) = systemd::notify_watchdog().await {
            tracing::error!(error = format!("{err:#}"), "systemd::notify_watchdog");
        }

        let client_certificate_expiry_unix_epoch_secs =
            self.forge_client_config.client_cert_expiry().await;

        self.client_cert_renewer
            .renew_certificates_if_necessary(Some(certs))
            .await;

        let loop_period = Duration::from_secs(self.agent_config.period.main_loop_idle_secs);

        tracing::info!(
            cert_expiry = %dt(client_certificate_expiry_unix_epoch_secs
                .map(|secs| Duration::from_secs(secs.max(0) as u64))
                .unwrap_or(Duration::from_secs(0))),
            loop_duration = %dt(loop_start.elapsed()),
            uptime = %dt(self.started_at.elapsed()),
            "loop metrics",
        );

        Ok(IterationResult {
            stop_agent: false,
            loop_period,
        })
    }
}
