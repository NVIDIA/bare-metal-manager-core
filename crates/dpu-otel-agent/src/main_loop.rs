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

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ::rpc::forge_tls_client::ForgeClientConfig;
use carbide_host_support::agent_config::AgentConfig;
use carbide_systemd::systemd;
use forge_certs::cert_renewal::ClientCertRenewer;
use forge_tls::client_config::ClientCert;
use humantime::format_duration as dt;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;
use typed_builder::TypedBuilder;

use crate::command_line;

const SECONDS_IN_DAY: u64 = 86400;

#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("Processing interrupted by TERM signal")]
    Interrupted,
}

pub async fn setup_and_run(
    forge_client_config: Arc<ForgeClientConfig>,
    agent_config: AgentConfig,
    options: command_line::RunOptions,
) -> eyre::Result<()> {
    systemd::notify_start().await?;
    tracing::info!(
        options = ?options,
        "Started forge-dpu-otel-agent"
    );

    let start = Instant::now();
    let client_cert: &String = &agent_config.forge_system.client_cert;
    let client_key: &String = &agent_config.forge_system.client_key;

    // Setup client certificate renewal
    let forge_api_server = agent_config.forge_system.api_server.clone();
    let mut client_cert_renewer =
        ClientCertRenewer::new(forge_api_server.clone(), Arc::clone(&forge_client_config));

    // If the configured certs do not exist, copy them to the configured path from existing certs
    // specified in the run args. If they do exist, also check that they are not more than a day
    // old, in case this agent hasn't run in a while.
    if !Path::new(client_cert).exists()
        || is_file_older_than(client_cert, Duration::from_secs(SECONDS_IN_DAY))
    {
        if let Some(source_tls_cert_path) = options.source_tls_cert_path.as_ref() {
            let copy_loop = CopyCertsLoop::builder()
                .config(&agent_config)
                .src(source_tls_cert_path)
                .dst(client_cert)
                .client_cert_renewer(&mut client_cert_renewer)
                .started_at(start)
                .build();

            match copy_loop.run().await {
                Ok(_) => {}
                Err(e) => match e.downcast_ref::<ProcessingError>() {
                    Some(ProcessingError::Interrupted) => {
                        return Ok(());
                    }
                    _ => return Err(e),
                },
            }
        } else {
            return Err(eyre::eyre!(
                "No source_tls_cert_path specified in run options"
            ));
        }
    } else {
        tracing::info!("Found recent {:?}, skipped cert copy", client_cert);
    }

    if !Path::new(client_key).exists()
        || is_file_older_than(client_key, Duration::from_secs(SECONDS_IN_DAY))
    {
        if let Some(source_tls_key_path) = options.source_tls_key_path.as_ref() {
            let copy_loop = CopyCertsLoop::builder()
                .config(&agent_config)
                .src(source_tls_key_path)
                .dst(client_key)
                .client_cert_renewer(&mut client_cert_renewer)
                .started_at(start)
                .build();

            match copy_loop.run().await {
                Ok(_) => {}
                Err(e) => match e.downcast_ref::<ProcessingError>() {
                    Some(ProcessingError::Interrupted) => {
                        return Ok(());
                    }
                    _ => return Err(e),
                },
            }
        } else {
            return Err(eyre::eyre!(
                "No source_tls_key_path specified in run options",
            ));
        }
    } else {
        tracing::info!("Found recent {:?}, skipped cert copy", client_key);
    }

    let main_loop = MainLoop {
        agent_config,
        client_cert_renewer,
        started_at: start,
    };

    main_loop.run().await
}

#[derive(TypedBuilder)]
struct CopyCertsLoop<'a> {
    // required
    config: &'a AgentConfig,
    src: &'a PathBuf,
    dst: &'a String,
    client_cert_renewer: &'a mut ClientCertRenewer,
    started_at: Instant,

    // optional
    #[builder(default = 1.5)]
    backoff_factor: f64,
    #[builder(default = 5)]
    max_interval_repeated_count: u64,

    // internal state
    #[builder(default = 1, setter(skip))]
    interval: u64,
    #[builder(default, setter(skip))]
    interval_repeated_count: u64,
    #[builder(default = None, setter(skip))]
    last_watchdog_notify: Option<Instant>,
    #[builder(default, setter(skip))]
    max_interval_reached: bool,
}

struct MainLoop {
    agent_config: AgentConfig,
    client_cert_renewer: ClientCertRenewer,
    started_at: Instant,
}

struct IterationResult {
    stop: bool,
    loop_period: Duration,
}

impl CopyCertsLoop<'_> {
    async fn run(mut self) -> Result<(), eyre::Report> {
        let mut term_signal = signal(SignalKind::terminate())?;
        let mut hup_signal = signal(SignalKind::hangup())?;

        loop {
            let result = self.run_single_iteration().await?;
            if result.stop {
                return Ok(());
            }

            tokio::select! {
                biased;
                _ = term_signal.recv() => {
                    systemd::notify_stop().await?;
                    tracing::info!("TERM signal received, clean exit");
                    return Err(ProcessingError::Interrupted.into());
                }
                _ = hup_signal.recv() => {
                    self.reinit();
                    tracing::info!("Hangup received, reinitialized");
                }
                _ = sleep(result.loop_period) => {}
            }
        }
    }

    /// Runs a single iteration of the init certs loop
    async fn run_single_iteration(&mut self) -> Result<IterationResult, eyre::Report> {
        let iteration_start = Instant::now();

        if let Some(last_notify) = self.last_watchdog_notify {
            if last_notify.elapsed() >= self.min_watchdog_notify_interval() {
                notify_watchdog().await;
                self.last_watchdog_notify = Some(Instant::now());
            }
        } else {
            notify_watchdog().await;
            self.last_watchdog_notify = Some(Instant::now());
        }

        // re-check the destination path in case the configured certs were added
        if Path::new(self.dst).exists()
            && !is_file_older_than(self.dst, Duration::from_secs(SECONDS_IN_DAY))
        {
            tracing::info!(
                "{:?} recently added, skipping copy from {:?}",
                self.dst,
                self.src,
            );
            return Ok(IterationResult {
                stop: true,
                loop_period: Duration::from_secs(0),
            });
        }

        if self.src.exists() {
            tokio::fs::copy(self.src, self.dst).await?;
            self.client_cert_renewer.renew_on_next_check();
            tracing::info!(
                "File copied successfully from {:?} to {:?}",
                self.src,
                self.dst,
            );
            return Ok(IterationResult {
                stop: true,
                loop_period: Duration::from_secs(0),
            });
        }

        if self.max_interval_reached {
            // Leave max interval unchanged
        } else if self.interval >= self.max_interval() {
            tracing::error!(
                "Maximum interval reached. Continue to try every {}.",
                humantime::format_duration(Duration::from_secs(self.max_interval())),
            );
            self.max_interval_reached = true;
        } else if self.interval_repeated_count >= self.max_interval_repeated_count {
            // Increase interval with exponential backoff
            self.interval = std::cmp::min(
                (self.interval as f64 * self.backoff_factor).round() as u64,
                self.max_interval(),
            );
            self.interval_repeated_count = 0;
        } else {
            self.interval_repeated_count += 1;
        }

        tracing::info!(
            "{:?} not found. Try again in {}.",
            self.src,
            humantime::format_duration(Duration::from_secs(self.interval)),
        );

        let loop_period = Duration::from_secs(self.interval);

        tracing::info!(
            iteration = %dt(iteration_start.elapsed()),
            uptime = %dt(self.started_at.elapsed()),
            "copy certs loop",
        );

        Ok(IterationResult {
            stop: false,
            loop_period,
        })
    }

    fn max_interval(&mut self) -> u64 {
        self.config.period.main_loop_idle_secs
    }

    fn min_watchdog_notify_interval(&mut self) -> Duration {
        Duration::from_secs(self.config.period.main_loop_active_secs)
    }

    fn reinit(&mut self) {
        let init = CopyCertsLoop::builder()
            .config(self.config)
            .src(self.src)
            .dst(self.dst)
            .client_cert_renewer(self.client_cert_renewer)
            .started_at(self.started_at)
            .build();
        self.interval = init.interval;
        self.interval_repeated_count = init.interval_repeated_count;
        self.last_watchdog_notify = init.last_watchdog_notify;
        self.max_interval_reached = init.max_interval_reached;
    }
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
            if result.stop {
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
                _ = sleep(result.loop_period) => {}
            }
        }
    }

    /// Runs a single iteration of the main loop
    async fn run_single_iteration(
        &mut self,
        certs: &ClientCert,
    ) -> Result<IterationResult, eyre::Report> {
        let iteration_start = Instant::now();

        notify_watchdog().await;

        self.client_cert_renewer
            .renew_certificates_if_necessary(Some(certs))
            .await;

        let loop_period = Duration::from_secs(self.agent_config.period.main_loop_idle_secs);

        tracing::info!(
            iteration = %dt(iteration_start.elapsed()),
            uptime = %dt(self.started_at.elapsed()),
            "main cert renewal loop",
        );

        Ok(IterationResult {
            stop: false,
            loop_period,
        })
    }
}

fn is_file_older_than(path: &str, duration: Duration) -> bool {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .map(|since| since > duration)
        .unwrap_or(false)
}

async fn notify_watchdog() {
    if let Err(err) = systemd::notify_watchdog().await {
        tracing::error!(error = format!("{err:#}"), "systemd::notify_watchdog");
    }
}
