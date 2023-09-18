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

use std::sync::Arc;

use axum::http::StatusCode;
use axum::{extract::Path, extract::State, routing::get, Router};

use crate::instance_metadata_fetcher::InstanceMetadataReader;

const PUBLIC_IPV4_CATEGORY: &str = "public-ipv4";
const HOSTNAME_CATEGORY: &str = "hostname";
const USER_DATA_CATEGORY: &str = "user-data";

pub fn get_instance_metadata_router(metadata_fetcher: Arc<dyn InstanceMetadataReader>) -> Router {
    // TODO add handling for non-supported URIs
    Router::new()
        .route("/:category", get(get_metadata_parameter))
        .with_state(metadata_fetcher)
}

async fn get_metadata_parameter(
    State(state): State<Arc<dyn InstanceMetadataReader>>,
    Path(category): Path<String>,
) -> (StatusCode, String) {
    if let Some(metadata) = state.read().as_ref() {
        return match category.as_str() {
            PUBLIC_IPV4_CATEGORY => (StatusCode::OK, metadata.address.clone()),
            HOSTNAME_CATEGORY => (StatusCode::OK, metadata.hostname.clone()),
            USER_DATA_CATEGORY => (StatusCode::OK, metadata.user_data.clone()),
            _ => (
                StatusCode::NOT_FOUND,
                format!("metadata category not found: {}", category),
            ),
        };
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "metadata currently unavailable".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance_metadata_fetcher::{InstanceMetadata, MockInstanceMetadataReader};
    use axum::http;

    async fn setup_server(
        metadata: Option<InstanceMetadata>,
    ) -> (tokio::task::JoinHandle<()>, u16) {
        let mut _mock_reader = MockInstanceMetadataReader::new();
        _mock_reader
            .expect_read()
            .times(1)
            .return_const(Arc::new(metadata.clone()));

        let mock_reader = Arc::new(_mock_reader);

        let router = get_instance_metadata_router(mock_reader.clone());

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let std_listener = listener.into_std().unwrap();

        let server = tokio::spawn(async move {
            hyper::Server::from_tcp(std_listener)
                .unwrap()
                .serve(router.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        (server, server_port)
    }

    async fn send_request_and_check_response(
        port: u16,
        path: &str,
        expected_body: &str,
        expected_code: http::StatusCode,
    ) {
        let client = hyper::Client::new();
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!("http://127.0.0.1:{}/{}", port, path))
            .body(hyper::Body::empty())
            .unwrap();

        let response = client.request(request).await.unwrap();

        assert_eq!(response.status(), expected_code);

        if expected_code == StatusCode::OK {
            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = std::str::from_utf8(&body).unwrap();

            assert_eq!(body_str, expected_body);
        }
    }

    #[tokio::test]
    async fn test_get_metadata_parameter_public_ipv4_category() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "public-ipv4",
            &metadata.address,
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_metadata_parameter_hostname_category() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "hostname",
            &metadata.hostname,
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_metadata_parameter_user_data_category() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "user-data",
            &metadata.user_data,
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_server_error_on_empty_metadata() {
        let (server, server_port) = setup_server(None).await;
        send_request_and_check_response(
            server_port,
            "hostname",
            "",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        server.abort();
    }
}
