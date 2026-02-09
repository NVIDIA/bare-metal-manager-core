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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use model::resource_pool::ResourcePoolStats;
use prometheus_text_parser::ParsedPrometheusMetrics;
use sqlx::PgPool;

use crate::logging::service_health_metrics::{
    ServiceHealthContext, start_export_service_health_metrics,
};
use crate::tests::common::test_meter::TestMeter;

#[crate::sqlx_test]
async fn test_service_health_metrics(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let test_meter = TestMeter::default();
    let context = ServiceHealthContext {
        meter: test_meter.meter(),
        database_pool: pool,
        resource_pool_stats: Arc::new(Mutex::new(HashMap::from([
            (
                "pool1".to_string(),
                ResourcePoolStats { used: 10, free: 20 },
            ),
            (
                "pool2".to_string(),
                ResourcePoolStats { used: 20, free: 10 },
            ),
        ]))),
    };
    start_export_service_health_metrics(context);

    let expected_metrics = include_str!("metrics_fixtures/test_service_health_metrics.txt")
        .parse::<ParsedPrometheusMetrics>()
        .unwrap()
        .scrub_build_attributes();
    let metrics = test_meter
        .export_metrics()
        .parse::<ParsedPrometheusMetrics>()
        .unwrap()
        .scrub_build_attributes();

    assert_eq!(expected_metrics, metrics);

    Ok(())
}
