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
use std::sync::Arc;

use carbide_secrets::certificates::CertificateProvider;
use carbide_secrets::credentials::CredentialManager;
use carbide_utils::HostPortPair;
use sqlx::PgPool;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::cfg::file::{CarbideConfig, InitialObjectsConfig};
use crate::dynamic_settings::DynamicSettings;
use crate::listener::AdminUiRoutesBuilder;
use crate::secrets::SecretsContext;
use crate::{CarbideError, setup};

/// Inputs prepared by the top-level `carbide-api` composition crate before
/// core service initialization begins.
#[doc(hidden)]
pub struct CoreRunInputs<'a> {
    pub carbide_config: Arc<CarbideConfig>,
    pub initial_objects: Option<InitialObjectsConfig>,
    pub meter: opentelemetry::metrics::Meter,
    /// The dedicated per-object state metrics registry, `None` when the
    /// opt-in endpoint is disabled. Created (and served) by the composition
    /// crate; core registers the per-object collectors on it.
    pub per_object_metrics: Option<prometheus::Registry>,
    pub join_set: &'a mut JoinSet<()>,
    pub dynamic_settings: DynamicSettings,
    pub credential_manager: Arc<dyn CredentialManager>,
    pub certificate_provider: Arc<dyn CertificateProvider>,
    pub db_pool: PgPool,
    pub secrets_context: Option<SecretsContext>,
    pub admin_ui_routes_builder: Option<AdminUiRoutesBuilder>,
    pub cancel_token: CancellationToken,
    pub ready_channel: Sender<()>,
}
/// Run the carbide-api server until `cancel_token` is cancelled.
///
/// `admin_ui_routes_builder` is how the admin web UI's pages (everything under
/// `/admin`) get plugged in: pass `Some(Box::new(carbide_api_web::routes))` to
/// serve them, or `None` to skip the web UI entirely (e.g. in-process test
/// servers, which only hit the gRPC API). It's passed in rather than called
/// directly to avoid a dependency cycle — see [`AdminUiRoutesBuilder`] for why.
///
/// Note: even when `Some` is passed, the admin UI is only mounted if the
/// `enable_admin_ui` config flag is true (the default). When it's false,
/// `start_api` drops the builder and serves gRPC only — so `Some` here means
/// "offer the UI", not "force it on". The flag also gates the log-stream
/// layer feeding the UI's live log viewer: with the UI off, no per-event
/// work is spent collecting lines nothing can read.
#[doc(hidden)]
pub async fn run_core(inputs: CoreRunInputs<'_>) -> eyre::Result<()> {
    let CoreRunInputs {
        carbide_config,
        initial_objects,
        meter,
        per_object_metrics,
        join_set,
        dynamic_settings,
        credential_manager,
        certificate_provider,
        db_pool,
        secrets_context,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    } = inputs;

    let redfish_pool = {
        let rf_pool = libredfish::RedfishClientPool::builder()
            .danger_accept_invalid_certs()
            .build()
            .map_err(CarbideError::from)?;

        // Support deprecated configuration for site_explorer.override_target_ip and override_target_port. Configuration should migrate to site_explorer.bmc_proxy.
        match (
            &carbide_config.site_explorer.override_target_ip,
            carbide_config.site_explorer.override_target_port,
            carbide_config.site_explorer.bmc_proxy.load().as_ref(),
        ) {
            (Some(_), _, Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_ip, since site_explorer.bmc_proxy is also set. Please delete override_target_ip from site_explorer config."
                );
            }
            (Some(ip), maybe_target_port, None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_ip in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                if let Some(port) = maybe_target_port {
                    carbide_config.site_explorer.bmc_proxy.store(Arc::new(Some(
                        HostPortPair::HostAndPort(ip.to_string(), port),
                    )));
                } else {
                    carbide_config
                        .site_explorer
                        .bmc_proxy
                        .store(Arc::new(Some(HostPortPair::HostOnly(ip.to_string()))));
                }
            }
            (None, Some(port), None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_port in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                carbide_config
                    .site_explorer
                    .bmc_proxy
                    .store(Arc::new(Some(HostPortPair::PortOnly(port))));
            }
            (None, Some(_), Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_port, since site_explorer.bmc_proxy is also set. Please delete override_target_port from site_explorer config."
                );
            }
            (None, None, _) => {} // leave bmc_proxy untouched
        }

        carbide_redfish::libredfish::new_pool(
            credential_manager.clone(),
            rf_pool,
            carbide_config.site_explorer.bmc_proxy.clone(),
        )
    };

    let nv_redfish_pool =
        carbide_redfish::nv_redfish::new_pool(carbide_config.site_explorer.bmc_proxy.clone());

    setup::start_api(
        join_set,
        carbide_config,
        initial_objects,
        meter,
        per_object_metrics,
        dynamic_settings,
        redfish_pool,
        nv_redfish_pool,
        credential_manager,
        certificate_provider,
        db_pool,
        secrets_context,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    )
    .await?;

    Ok(())
}
