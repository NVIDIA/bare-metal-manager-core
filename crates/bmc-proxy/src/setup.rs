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

use metrics_endpoint::MetricsSetup;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(thiserror::Error, Debug)]
pub enum SetupError {
    #[error("error configuring logging from environment variables: {0}")]
    EnvFilter(#[from] tracing_subscriber::filter::FromEnvError),
    #[error("error initializing tracing subscriber: {0}")]
    TracingSubscriberInit(#[from] tracing_subscriber::util::TryInitError),
    #[error("error setting up metrics: {0}")]
    Metrics(String),
}

pub type SetupResult<T> = Result<T, SetupError>;

pub fn setup_logging(debug: bool) -> SetupResult<()> {
    // Default log level if RUST_LOG is not set
    let default_log_level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    // Ignore certain spans and events from 3rd party frameworks
    let log_filter = dep_log_filter(
        EnvFilter::builder()
            .with_default_directive(default_log_level.into())
            .from_env()?,
    );

    let log_events = carbide_instrument::LogEventsMetric::new("nico-bmc-proxy");
    tracing_subscriber::registry()
        .with(log_events.layer().with_filter(log_filter.clone()))
        .with(
            logfmt::layer()
                .with_event_fields([logfmt::EventField::with_default(
                    "component",
                    "nico-bmc-proxy",
                )])
                .with_filter(log_filter),
        )
        .try_init()?;

    tracing::info!(configured_log_level = %LevelFilter::current(), "current log level");
    Ok(())
}

pub fn setup_metrics() -> SetupResult<MetricsSetup> {
    metrics_endpoint::new_metrics_setup("carbide-bmc-proxy", "carbide-system", true)
        .map_err(|e| SetupError::Metrics(e.to_string()))
}

pub fn dep_log_filter(env_filter: EnvFilter) -> EnvFilter {
    [
        "hyper=error",
        "rustls=warn",
        "tokio_util::codec=warn",
        "vaultrs=error",
        "h2=warn",
    ]
    .iter()
    .fold(env_filter, |f, filter_str| {
        f.add_directive(
            filter_str
                .parse()
                .unwrap_or_else(|err| panic!("{filter_str} must be parsed; error: {err}")),
        )
    })
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    #[derive(Clone, Copy)]
    enum FilterCase {
        DefaultAllowsApplicationInfo,
        DefaultSuppressesHyperInfo,
        DefaultAllowsHyperError,
        UserOverrideAllowsApplicationDebug,
        DependencyCapOverridesVaultrsDebug,
        UserOverrideDoesNotAffectHyperCap,
    }

    fn filter_allows(case: FilterCase) -> bool {
        let directives = match case {
            FilterCase::DefaultAllowsApplicationInfo
            | FilterCase::DefaultSuppressesHyperInfo
            | FilterCase::DefaultAllowsHyperError => "info",
            FilterCase::UserOverrideAllowsApplicationDebug => "info,carbide_bmc_proxy=debug",
            FilterCase::DependencyCapOverridesVaultrsDebug
            | FilterCase::UserOverrideDoesNotAffectHyperCap => "info,vaultrs=debug",
        };
        let user = EnvFilter::builder().parse(directives).unwrap();
        let subscriber = tracing_subscriber::registry().with(dep_log_filter(user));

        tracing::subscriber::with_default(subscriber, || match case {
            FilterCase::DefaultAllowsApplicationInfo => {
                tracing::enabled!(target: "carbide_bmc_proxy", tracing::Level::INFO)
            }
            FilterCase::DefaultSuppressesHyperInfo => {
                tracing::enabled!(target: "hyper", tracing::Level::INFO)
            }
            FilterCase::DefaultAllowsHyperError => {
                tracing::enabled!(target: "hyper", tracing::Level::ERROR)
            }
            FilterCase::UserOverrideAllowsApplicationDebug => {
                tracing::enabled!(target: "carbide_bmc_proxy", tracing::Level::DEBUG)
            }
            FilterCase::DependencyCapOverridesVaultrsDebug => {
                tracing::enabled!(target: "vaultrs", tracing::Level::DEBUG)
            }
            FilterCase::UserOverrideDoesNotAffectHyperCap => {
                tracing::enabled!(target: "hyper", tracing::Level::INFO)
            }
        })
    }

    #[test]
    fn dependency_log_filter_applies_caps_and_user_overrides() {
        value_scenarios!(
            run = filter_allows;
            "application info allowed by default directive" {
                FilterCase::DefaultAllowsApplicationInfo => true,
            }

            "hyper info suppressed by dependency cap" {
                FilterCase::DefaultSuppressesHyperInfo => false,
            }

            "hyper error allowed by dependency cap" {
                FilterCase::DefaultAllowsHyperError => true,
            }

            "user override allows application debug" {
                FilterCase::UserOverrideAllowsApplicationDebug => true,
            }

            "dependency cap overrides vaultrs debug" {
                FilterCase::DependencyCapOverridesVaultrsDebug => false,
            }

            "user override leaves unrelated dependency capped" {
                FilterCase::UserOverrideDoesNotAffectHyperCap => false,
            }
        );
    }

    #[test]
    fn metrics_setup_initializes_health_controller() {
        // Mirrors setup_metrics() without its global-meter install: the
        // process-wide test meter (installed at load by
        // carbide_instrument::testing) owns instrument bindings for this
        // binary's event tests, and swapping the global provider mid-run
        // would steal first-emit bindings from them.
        let setup =
            metrics_endpoint::new_metrics_setup("carbide-bmc-proxy", "carbide-system", false)
                .expect("metrics setup succeeds");

        assert!(setup.health_controller.is_ready());
        assert!(setup.health_controller.is_healthy());
    }
}
