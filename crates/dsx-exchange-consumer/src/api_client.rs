/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Carbide API client for submitting rack health reports.

use std::str::FromStr;

use async_trait::async_trait;
use carbide_uuid::rack::RackId;
use forge_tls::client_config::ClientCert;
use health_report::HealthReport;
use rpc::forge::{
    HealthReportOverride, InsertRackHealthReportOverrideRequest, OverrideMode,
    RemoveRackHealthReportOverrideRequest,
};
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use url::Url;

use crate::DsxConsumerError;

/// Source identifier for health report overrides from this consumer.
pub const HEALTH_REPORT_SOURCE: &str = "dsx-exchange-consumer";

/// Trait for submitting rack health reports.
#[async_trait]
pub trait RackHealthReportSink: Send + Sync {
    async fn insert_rack_health_report(
        &self,
        rack_id: &str,
        report: HealthReport,
    ) -> Result<(), DsxConsumerError>;

    async fn remove_rack_health_report(&self, rack_id: &str) -> Result<(), DsxConsumerError>;
}

/// API client wrapper for Carbide API communication.
#[derive(Clone)]
pub struct ApiClientWrapper {
    client: ForgeApiClient,
}

impl ApiClientWrapper {
    pub fn new(root_ca: String, client_cert: String, client_key: String, api_url: &Url) -> Self {
        let client_config = ForgeClientConfig::new(
            root_ca,
            Some(ClientCert {
                cert_path: client_cert,
                key_path: client_key,
            }),
        );
        let api_config = ApiConfig::new(api_url.as_str(), &client_config);

        let client = ForgeApiClient::new(&api_config);

        Self { client }
    }
}

#[async_trait]
impl RackHealthReportSink for ApiClientWrapper {
    async fn insert_rack_health_report(
        &self,
        rack_id: &str,
        report: HealthReport,
    ) -> Result<(), DsxConsumerError> {
        let rack_id = parse_rack_id(rack_id)?;
        let request = InsertRackHealthReportOverrideRequest {
            rack_id: Some(rack_id),
            r#override: Some(HealthReportOverride {
                report: Some(report.into()),
                mode: OverrideMode::Merge.into(),
            }),
        };

        self.client
            .insert_rack_health_report_override(request)
            .await?;

        Ok(())
    }

    async fn remove_rack_health_report(&self, rack_id: &str) -> Result<(), DsxConsumerError> {
        let rack_id = parse_rack_id(rack_id)?;
        let request = RemoveRackHealthReportOverrideRequest {
            rack_id: Some(rack_id),
            source: HEALTH_REPORT_SOURCE.to_string(),
        };

        self.client
            .remove_rack_health_report_override(request)
            .await?;

        Ok(())
    }
}

/// Console sink for debugging - logs rack health reports to console.
pub struct ConsoleRackHealthSink;

#[async_trait]
impl RackHealthReportSink for ConsoleRackHealthSink {
    async fn insert_rack_health_report(
        &self,
        rack_id: &str,
        report: HealthReport,
    ) -> Result<(), DsxConsumerError> {
        tracing::info!(
            rack_id = %rack_id,
            "Inserting rack health override: {} successes and {} alerts",
            report.successes.len(),
            report.alerts.len()
        );
        for alert in &report.alerts {
            tracing::warn!(rack_id = %rack_id, alert = ?alert, "Rack health alert");
        }
        Ok(())
    }

    async fn remove_rack_health_report(&self, rack_id: &str) -> Result<(), DsxConsumerError> {
        tracing::info!(
            rack_id = %rack_id,
            source = HEALTH_REPORT_SOURCE,
            "Removing rack health override"
        );
        Ok(())
    }
}

// for error mapping convenience
fn parse_rack_id(rack_id: &str) -> Result<RackId, DsxConsumerError> {
    RackId::from_str(rack_id).map_err(|e| {
        DsxConsumerError::Api(tonic::Status::invalid_argument(format!(
            "Invalid rack ID: {e}"
        )))
    })
}
