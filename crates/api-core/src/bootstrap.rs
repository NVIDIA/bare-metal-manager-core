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

use std::sync::Arc;

use carbide_rack::rms_node_type::warn_rms_node_descriptor_attribute_overrides;
use carbide_secrets::certificates::CertificateProvider;
use carbide_secrets::credentials::CredentialManager;
use sqlx::PgPool;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub use crate::api::metrics::ApiMetricsEmitter;
use crate::cfg::file::{CarbideConfig, InitialObjectsConfig};
use crate::dynamic_settings::DynamicSettings;
use crate::listener::AdminUiRoutesBuilder;
pub use crate::logging::level_filter::{ActiveLevel, ReloadableFilter};
pub use crate::logging::setup::{Logging, dep_log_filter};
pub use crate::logging::stream::LogStreamLayer;
use crate::secrets::SecretsContext;

/// Opaque core runtime state initialized before external resources.
#[doc(hidden)]
pub struct RuntimePrelude {
    dynamic_settings: DynamicSettings,
}

/// Starts the core runtime work that follows logging initialization and precedes
/// external resource initialization.
///
/// Rack-profile attribute override collisions are logged once here so the
/// configured tracing subscriber receives the diagnostics.
#[doc(hidden)]
pub fn start_runtime_prelude(
    carbide_config: &CarbideConfig,
    logging: Logging,
    join_set: &mut JoinSet<()>,
    cancel_token: &CancellationToken,
) -> RuntimePrelude {
    // These diagnostics require the tracing subscriber installed by the caller.
    warn_rms_node_descriptor_attribute_overrides(&carbide_config.rack_profiles);

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

    RuntimePrelude { dynamic_settings }
}

/// Prepared resources passed through the cross-crate runtime boundary.
#[doc(hidden)]
pub struct RuntimeInputs<'a> {
    pub carbide_config: Arc<CarbideConfig>,
    pub initial_objects: Option<InitialObjectsConfig>,
    pub meter: opentelemetry::metrics::Meter,
    pub per_object_metrics: Option<prometheus::Registry>,
    pub join_set: &'a mut JoinSet<()>,
    pub runtime_prelude: RuntimePrelude,
    pub credential_manager: Arc<dyn CredentialManager>,
    pub certificate_provider: Arc<dyn CertificateProvider>,
    pub db_pool: PgPool,
    pub secrets_context: Option<SecretsContext>,
    pub admin_ui_routes_builder: Option<AdminUiRoutesBuilder>,
    pub cancel_token: CancellationToken,
    pub ready_channel: Sender<()>,
}

/// Enter api-core's private service runtime with fully prepared resources.
///
/// `admin_ui_routes_builder` is how the admin web UI's pages (everything under
/// `/admin`) get plugged in: pass `Some(Box::new(carbide_api_web::routes))` to
/// serve them, or `None` to skip the web UI entirely (e.g. in-process test
/// servers, which only hit the gRPC API). It's passed in rather than called
/// directly to avoid a dependency cycle — see [`AdminUiRoutesBuilder`] for why.
///
/// Note: even when `Some` is passed, the admin UI is only mounted if the
/// `enable_admin_ui` config flag is true (the default). When it's false, the
/// core runtime drops the builder and serves gRPC only — so `Some` here means
/// "offer the UI", not "force it on". The flag also gates the log-stream
/// layer feeding the UI's live log viewer: with the UI off, no per-event
/// work is spent collecting lines nothing can read.
#[doc(hidden)]
pub async fn start_runtime(inputs: RuntimeInputs<'_>) -> eyre::Result<()> {
    let RuntimeInputs {
        carbide_config,
        initial_objects,
        meter,
        per_object_metrics,
        join_set,
        runtime_prelude,
        credential_manager,
        certificate_provider,
        db_pool,
        secrets_context,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    } = inputs;
    let RuntimePrelude { dynamic_settings } = runtime_prelude;

    crate::setup::start_runtime(
        join_set,
        carbide_config,
        initial_objects,
        meter,
        per_object_metrics,
        dynamic_settings,
        credential_manager,
        certificate_provider,
        db_pool,
        secrets_context,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    )
    .await
}

/// Acquire the session-level lock that serializes the one-time Vault import.
pub async fn lock_vault_import_session(
    connection: &mut sqlx::PgConnection,
) -> db::DatabaseResult<()> {
    db::secrets::lock_path_session(connection, crate::secrets::VAULT_IMPORT_MARKER_PATH).await
}
