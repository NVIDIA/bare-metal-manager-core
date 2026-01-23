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

use model::resource_pool::ResourcePoolStats;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;

pub struct ServiceHealthContext {
    pub meter: Meter,
    pub database_pool: sqlx::PgPool,
    pub resource_pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>>,
}

/// Starts to export server health metrics
pub fn start_export_service_health_metrics(health_context: ServiceHealthContext) {
    health_context
        .meter
        .u64_observable_gauge("carbide_api_ready")
        .with_description("Whether the Forge Site Controller API is running")
        .with_callback(|observer| {
            observer.observe(1, &[]);
        })
        .build();
    health_context
        .meter
        .u64_observable_gauge("carbide_api_version")
        .with_description("Version (git sha, build date, etc) of this service")
        .with_callback(|observer| {
            observer.observe(
                1,
                &[
                    KeyValue::new(
                        "build_version",
                        carbide_version::v!(build_version).to_string(),
                    ),
                    KeyValue::new("build_date", carbide_version::v!(build_date).to_string()),
                    KeyValue::new("git_sha", carbide_version::v!(git_sha).to_string()),
                    KeyValue::new(
                        "rust_version",
                        carbide_version::v!(rust_version).to_string(),
                    ),
                    KeyValue::new("build_user", carbide_version::v!(build_user).to_string()),
                    KeyValue::new(
                        "build_hostname",
                        carbide_version::v!(build_hostname).to_string(),
                    ),
                ],
            );
        })
        .build();

    {
        let database_pool = health_context.database_pool.clone();
        health_context
            .meter
            .u64_observable_gauge("carbide_db_pool_idle_conns")
            .with_description("The amount of idle connections in the carbide database pool")
            .with_callback(move |observer| {
                observer.observe(database_pool.num_idle() as u64, &[]);
            })
            .build();
    }

    {
        let database_pool = health_context.database_pool.clone();
        health_context
            .meter
            .u64_observable_gauge("carbide_db_pool_total_conns")
            .with_description(
                "The amount of total (active + idle) connections in the carbide database pool",
            )
            .with_callback(move |observer| {
                observer.observe(database_pool.size() as u64, &[]);
            })
            .build();
    }

    {
        let rp_stats = health_context.resource_pool_stats.clone();
        health_context
            .meter
            .u64_observable_gauge("carbide_resourcepool_used_count")
            .with_description("Count of values in the pool currently allocated")
            .with_callback(move |observer| {
                for (name, stats) in rp_stats.lock().unwrap().iter() {
                    observer.observe(
                        stats.used as u64,
                        &[KeyValue::new("pool", name.to_string())],
                    );
                }
            })
            .build();
    }

    {
        let rp_stats = health_context.resource_pool_stats.clone();
        health_context
            .meter
            .u64_observable_gauge("carbide_resourcepool_free_count")
            .with_description("Count of values in the pool currently available for allocation")
            .with_callback(move |observer| {
                for (name, stats) in rp_stats.lock().unwrap().iter() {
                    let name_attr = KeyValue::new("pool", name.to_string());
                    observer.observe(stats.free as u64, std::slice::from_ref(&name_attr));
                }
            })
            .build();
    }
}
