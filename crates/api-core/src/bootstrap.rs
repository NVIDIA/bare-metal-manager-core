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

//! Implementation interface for the top-level `carbide-api` composition crate.
//!
//! This is not a general-purpose library API. It groups the process-bootstrap
//! types that must cross the crate boundary while service implementation stays
//! in `carbide-api-core`.

pub use crate::api::metrics::ApiMetricsEmitter;
pub use crate::dynamic_settings::DynamicSettings;
pub use crate::logging::level_filter::{ActiveLevel, ReloadableFilter};
pub use crate::logging::setup::{Logging, dep_log_filter};
pub use crate::logging::stream::LogStreamLayer;
pub use crate::run::{CoreRunInputs, run_core};

/// Start the core runtime work that must precede external resource initialization.
pub fn start_core_runtime(
    carbide_config: &crate::cfg::file::CarbideConfig,
    logging: Logging,
    join_set: &mut tokio::task::JoinSet<()>,
    cancel_token: &tokio_util::sync::CancellationToken,
) -> DynamicSettings {
    // Redact credentials before printing the config
    let print_config = carbide_config.redacted();

    tracing::info!(
        print_config = ?print_config,
        "Using configuration",
    );
    tracing::info!(
        worker_count = tokio::runtime::Handle::current().metrics().num_workers(),
        cpu_count = num_cpus::get(),
        tokio_worker_threads = %std::env::var("TOKIO_WORKER_THREADS").unwrap_or_else(|_| "UNSET".to_string()),
        "Tokio worker thread configuration",
    );

    let dynamic_settings = DynamicSettings {
        log_filter: logging.filter.clone(),
        site_explorer_enabled: carbide_config.site_explorer.enabled.clone(),
        create_machines: carbide_config.site_explorer.create_machines.clone(),
        bmc_proxy: carbide_config.site_explorer.bmc_proxy.clone(),
        tracing_enabled: logging.tracing_enabled,
        log_stream: logging.log_stream,
    };
    dynamic_settings.start_reset_task(
        join_set,
        crate::dynamic_settings::RESET_PERIOD,
        cancel_token.clone(),
    );

    tracing::info!(
        listen_address = carbide_config.listen.to_string(),
        build_version = carbide_version::v!(build_version),
        build_date = carbide_version::v!(build_date),
        rust_version = carbide_version::v!(rust_version),
        "Start carbide-api",
    );

    dynamic_settings
}

/// Acquire the session-level lock that serializes the one-time Vault import.
pub async fn lock_vault_import_session(
    connection: &mut sqlx::PgConnection,
) -> db::DatabaseResult<()> {
    db::secrets::lock_path_session(connection, crate::secrets::VAULT_IMPORT_MARKER_PATH).await
}
