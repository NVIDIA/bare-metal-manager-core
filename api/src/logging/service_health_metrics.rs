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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;

use crate::resource_pool::ResourcePoolStats;

pub struct ServiceHealthContext {
    pub meter: Meter,
    pub database_pool: sqlx::PgPool,
    pub resource_pool_stats: Option<Arc<Mutex<HashMap<String, ResourcePoolStats>>>>,
}

/// Starts to export server health metrics
pub fn start_export_service_health_metrics(health_context: ServiceHealthContext) {
    let ready_metric = health_context
        .meter
        .u64_observable_gauge("carbide_api_ready")
        .with_description("Whether the Forge Site Controller API is running")
        .init();

    let db_pool_total_conns_metric = health_context
        .meter
        .u64_observable_gauge("carbide_db_pool_total_conns")
        .with_description(
            "The amount of total (active + idle) connections in the carbide database pool",
        )
        .init();
    let db_pool_idle_conns_metric = health_context
        .meter
        .u64_observable_gauge("carbide_db_pool_idle_conns")
        .with_description("The amount of idle connections in the carbide database pool")
        .init();

    let pool_used = health_context
        .meter
        .u64_observable_gauge("carbide_resourcepool_used_count")
        .with_description("Count of values in the pool currently allocated")
        .init();
    let pool_free = health_context
        .meter
        .u64_observable_gauge("carbide_resourcepool_free_count")
        .with_description("Count of values in the pool currently available for allocation")
        .init();

    // The metrics is queried inside the callback by the opentelemetry framework
    // Since it's emitted as long as the service is running, there is nothing else
    // to do
    let meter = health_context.meter.clone();
    meter
        .register_callback(move |cx| {
            ready_metric.observe(cx, 1, &[]);

            db_pool_total_conns_metric.observe(cx, health_context.database_pool.size() as u64, &[]);
            db_pool_idle_conns_metric.observe(
                cx,
                health_context.database_pool.num_idle() as u64,
                &[],
            );

            if let Some(rp_stats) = &health_context.resource_pool_stats {
                for (name, stats) in rp_stats.lock().unwrap().iter() {
                    let name_attr = KeyValue::new("pool", name.to_string());
                    pool_used.observe(cx, stats.used as u64, &[name_attr.clone()]);
                    pool_free.observe(cx, stats.free as u64, &[name_attr]);
                }
            }
        })
        .unwrap();
}
