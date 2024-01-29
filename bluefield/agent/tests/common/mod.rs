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

use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

use axum::http::header;
use axum::response::IntoResponse;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Body;

const TLS_CERT: &[u8] = include_bytes!("../../test-certs/tls.crt");
const TLS_KEY: &[u8] = include_bytes!("../../test-certs/tls.key");

pub async fn run_grpc_server(
    app: axum::Router<(), Body>,
) -> eyre::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?; // 0 let OS choose available port
    let addr = listener.local_addr()?;
    let join_handle = tokio::spawn(async move {
        let config = RustlsConfig::from_pem(TLS_CERT.to_vec(), TLS_KEY.to_vec())
            .await
            .unwrap();
        axum_server::from_tcp_rustls(listener, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    wait_for_server_to_start(addr).await?;

    Ok((addr, join_handle))
}

async fn wait_for_server_to_start(addr: SocketAddr) -> eyre::Result<()> {
    let url = format!("https://{addr}/up");
    let deadline = Instant::now() + Duration::from_secs(2);
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()?;
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == reqwest::StatusCode::OK => {
                break;
            }
            Ok(resp) => {
                eyre::bail!(
                    "Invalid status code from /up on mock grpc server: {}",
                    resp.status(),
                );
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    if Instant::now() >= deadline {
        eyre::bail!("Timed out waiting for mock grpc server to start");
    }
    Ok(())
}

/// Takes an rpc object (built from rpc/proto/forge.proto) and turns into into a gRPC axum response
pub fn respond(out: impl prost::Message) -> impl IntoResponse {
    let msg_len = out.encoded_len() as u32;
    let mut body = Vec::with_capacity(1 + 4 + msg_len as usize);
    // first byte is compression: 0 means none
    body.push(0u8);
    // next four bytes are length as bigendian u32
    body.extend_from_slice(&msg_len.to_be_bytes());
    // and finally the message
    out.encode(&mut body).unwrap();

    let headers = [(header::CONTENT_TYPE, "application/grpc+tonic")];
    (headers, body)
}
