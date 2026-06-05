//
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Integration test: issues Hello RPC to an NMX-C gRPC endpoint.
// Set NMXC_GRPC_ENDPOINT to run against a real server (e.g. http://127.0.0.1:50051).
// Insecure / plain HTTP is acceptable for local testing.
//

use libnmxc::{Endpoint, NmxcClientPool};

fn test_endpoint() -> Option<String> {
    std::env::var("NMXC_GRPC_ENDPOINT").ok()
}

#[tokio::test]
async fn hello_to_grpc_endpoint() {
    let endpoint_url = match test_endpoint() {
        Some(url) => url,
        None => {
            eprintln!(
                "Skipping hello test: set NMXC_GRPC_ENDPOINT to run (e.g. http://127.0.0.1:50051)"
            );
            return;
        }
    };

    let pool = NmxcClientPool::builder().build().expect("pool build");
    let endpoint = Endpoint::new(&endpoint_url).expect("parse NMX-C endpoint URI");
    let mut client = pool.create_client(endpoint).await.expect("create client");

    let response = client
        .hello("libnmxc-test-gateway")
        .await
        .expect("hello RPC");

    assert!(
        response.server_header.is_some(),
        "expected server_header in ServerHello"
    );
    let header = response.server_header.unwrap();
    assert_eq!(
        header.return_code,
        libnmxc::nmxc_model::StReturnCode::NmxStSuccess as i32,
        "expected return_code NMX_ST_SUCCESS"
    );
}
