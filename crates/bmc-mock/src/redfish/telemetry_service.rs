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

use std::borrow::Cow;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::{http, redfish};

/// Id of the single aggregated report the mock publishes.
pub const REPORT_ID: &str = "PlatformEnvironmentMetrics";

pub fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/TelemetryService"),
        odata_type: Cow::Borrowed("#TelemetryService.v1_3_1.TelemetryService"),
        id: Cow::Borrowed("TelemetryService"),
        name: Cow::Borrowed("Telemetry Service"),
    }
}

pub fn metric_reports_collection() -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Borrowed("/redfish/v1/TelemetryService/MetricReports"),
        odata_type: Cow::Borrowed("#MetricReportCollection.MetricReportCollection"),
        name: Cow::Borrowed("Metric Report Collection"),
    }
}

pub fn metric_report_resource<'a>(report_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("{}/{report_id}", metric_reports_collection().odata_id);
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#MetricReport.v1_5_0.MetricReport"),
        id: Cow::Borrowed(report_id),
        name: Cow::Borrowed("Metric Report"),
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    const REPORT_ID_PARAM: &str = "{report_id}";
    r.route(&resource().odata_id, get(get_telemetry_service))
        .route(
            &metric_reports_collection().odata_id,
            get(get_metric_reports),
        )
        .route(
            &metric_report_resource(REPORT_ID_PARAM).odata_id,
            get(get_metric_report),
        )
}

async fn get_telemetry_service() -> Response {
    resource()
        .json_patch()
        .patch(json!({
            "Status": redfish::resource::Status::Ok.into_json(),
            "ServiceEnabled": true,
        }))
        .patch(metric_reports_collection().nav_property("MetricReports"))
        .into_ok_response()
}

async fn get_metric_reports() -> Response {
    let members = [metric_report_resource(REPORT_ID).entity_ref()];
    metric_reports_collection()
        .with_members(&members)
        .into_ok_response()
}

async fn get_metric_report(
    State(state): State<BmcState>,
    Path(report_id): Path<String>,
) -> Response {
    if report_id != REPORT_ID {
        return http::not_found();
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    let metric_values: Vec<_> = sensor_metric_values(&state, &timestamp).collect();

    metric_report_resource(&report_id)
        .json_patch()
        .patch(json!({
            "Timestamp": timestamp,
            "MetricValues@odata.count": metric_values.len(),
            "MetricValues": metric_values,
        }))
        .into_ok_response()
}

fn sensor_metric_values<'a>(
    state: &'a BmcState,
    timestamp: &'a str,
) -> impl Iterator<Item = serde_json::Value> + 'a {
    state
        .chassis_state
        .iter()
        .flat_map(|chassis| {
            let id = chassis.config.id.as_ref();
            chassis
                .config
                .sensors
                .iter()
                .flatten()
                .map(move |s| (id, s))
        })
        .filter_map(move |(chassis_id, sensor)| {
            let reading = sensor.to_json().get("Reading")?.as_f64()?;
            let odata_id = redfish::sensor::chassis_resource(chassis_id, &sensor.id).odata_id;
            Some(json!({
                "MetricId": sensor.id,
                "MetricValue": reading.to_string(),
                "MetricProperty": odata_id,
                "Timestamp": timestamp,
            }))
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use nv_redfish::bmc_http::{BmcCredentials, HttpClient};
    use serde_json::json;
    use url::Url;

    use super::REPORT_ID;
    use crate::test_support::axum_http_client::AxumRouterHttpClient;
    use crate::test_support::{NoopCallbacks, TEST_MAC_POOL};
    use crate::{
        DpuMachineInfo, DpuSettings, HostHardwareType, HostMachineInfo, MachineInfo, machine_router,
    };

    fn test_host_mock() -> Router {
        let mut mac_pool = TEST_MAC_POOL.lock().unwrap();
        let hw_type = HostHardwareType::DellPowerEdgeR750;
        let ranges_config = mac_pool.allocate_range_config().unwrap();

        machine_router(
            &MachineInfo::Host(HostMachineInfo::new(
                hw_type,
                vec![DpuMachineInfo::new(
                    hw_type,
                    &mut mac_pool,
                    DpuSettings::default(),
                )],
                &mut mac_pool,
                ranges_config,
            )),
            Arc::new(NoopCallbacks),
            "test-host-id".to_string(),
            false,
        )
        .0
    }

    async fn get(
        client: &AxumRouterHttpClient,
        path: &str,
    ) -> Result<serde_json::Value, impl std::error::Error> {
        let url = Url::parse(&format!("https://bmc-mock.local{path}")).expect("valid URL");
        client
            .get(
                url,
                &BmcCredentials::new("root".to_string(), "password".to_string()),
                None,
                &axum::http::HeaderMap::new(),
            )
            .await
    }

    #[tokio::test]
    async fn telemetry_service_serves_sensor_readings_as_metric_report() {
        let router = test_host_mock();
        let client = AxumRouterHttpClient::new(router);

        let reports = "/redfish/v1/TelemetryService/MetricReports";

        // Service root advertises the service, which links the reports collection.
        let root = get(&client, "/redfish/v1").await.unwrap();
        assert_eq!(
            root["TelemetryService"]["@odata.id"],
            "/redfish/v1/TelemetryService"
        );
        let service = get(&client, "/redfish/v1/TelemetryService").await.unwrap();
        assert_eq!(service["ServiceEnabled"], true);
        assert_eq!(service["MetricReports"]["@odata.id"], reports);

        // The collection lists the single aggregated report.
        let collection = get(&client, reports).await.unwrap();
        assert_eq!(
            collection["Members"],
            json!([{ "@odata.id": format!("{reports}/{REPORT_ID}") }])
        );

        // Every value mirrors a chassis sensor reading.
        let report = get(&client, &format!("{reports}/{REPORT_ID}"))
            .await
            .unwrap();
        let values = report["MetricValues"].as_array().expect("MetricValues");
        assert!(!values.is_empty(), "report should mirror chassis sensors");
        assert_eq!(report["MetricValues@odata.count"], values.len());
        for value in values {
            value["MetricValue"]
                .as_str()
                .expect("MetricValue string")
                .parse::<f64>()
                .expect("numeric reading");
        }

        // Unknown report ids 404.
        assert!(get(&client, &format!("{reports}/Nope")).await.is_err());
    }
}
