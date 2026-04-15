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
