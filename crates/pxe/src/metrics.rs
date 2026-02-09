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
use std::time::Duration;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::time::sleep;

const TIME_BUCKETS: &[f64; 11] = &[
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0,
];

const SIZE_BUCKETS: &[f64; 9] = &[
    100.0,
    1000.0,
    10000.0,
    100000.0,
    1000000.0,
    10000000.0,
    100000000.0,
    1000000000.0,
    10000000000.0,
];

pub(crate) fn setup_prometheus() -> PrometheusHandle {
    let prometheus_builder = PrometheusBuilder::new()
        .add_global_label("system", "carbide-pxe")
        .add_global_label("build_version", carbide_version::v!(build_version))
        .add_global_label("build_date", carbide_version::v!(build_date))
        .add_global_label("rust_version", carbide_version::v!(rust_version))
        .add_global_label("build_hostname", carbide_version::v!(build_hostname))
        .set_buckets_for_metric(
            Matcher::Suffix("duration_seconds".to_string()),
            TIME_BUCKETS,
        )
        .expect("couldn't set prometheus buckets?")
        .set_buckets_for_metric(Matcher::Suffix("size_bytes".to_string()), SIZE_BUCKETS)
        .expect("couldn't set prometheus buckets?");

    let prometheus_handle = prometheus_builder
        .install_recorder()
        .expect("unable to install recorder?");

    let handle_clone = prometheus_handle.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        handle_clone.run_upkeep();
    });

    prometheus_handle
}
