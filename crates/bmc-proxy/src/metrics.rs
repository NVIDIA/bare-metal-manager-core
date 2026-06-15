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

use std::io;
use std::net::SocketAddr;

use metrics_endpoint::{MetricsEndpointConfig, MetricsSetup};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub async fn start(
    address: SocketAddr,
    metrics_setup: MetricsSetup,
    cancellation_token: CancellationToken,
    join_set: &mut JoinSet<()>,
) -> io::Result<()> {
    let listener = TcpListener::bind(&address).await?;
    tracing::info!(%address, "Starting metrics listener");

    join_set
        .build_task()
        .name("bmc-proxy metrics service")
        .spawn(async move {
            metrics_endpoint::run_metrics_endpoint_with_listener(
                &MetricsEndpointConfig {
                    address,
                    registry: metrics_setup.registry,
                    health_controller: Some(metrics_setup.health_controller),
                },
                cancellation_token,
                listener,
            )
            .await
        })
        // Safety: Should only fail if not in a tokio runtime
        .expect("Error spawning metrics endpoint");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn start_binds_listener_and_spawns_endpoint_task() {
        let address = "127.0.0.1:0".parse().expect("valid listen address");
        let metrics_setup =
            metrics_endpoint::new_metrics_setup("carbide-bmc-proxy-test", "test", false)
                .expect("metrics setup succeeds");
        let cancellation_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        start(
            address,
            metrics_setup,
            cancellation_token.clone(),
            &mut join_set,
        )
        .await
        .expect("metrics endpoint starts");

        assert_eq!(join_set.len(), 1);

        cancellation_token.cancel();
        timeout(Duration::from_secs(5), join_set.join_next())
            .await
            .expect("metrics endpoint exits after cancellation")
            .expect("metrics endpoint task is joined")
            .expect("metrics endpoint task succeeds");
    }
}
