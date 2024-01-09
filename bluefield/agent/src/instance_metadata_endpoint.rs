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
const GUID: &str = "guid";
const IB_PARTITION: &str = "partition";
const LID: &str = "lid";

pub fn get_instance_metadata_router(metadata_fetcher: Arc<dyn InstanceMetadataReader>) -> Router {
    // TODO add handling for non-supported URIs
    let ib_router = Router::new()
        .route("/devices", get(get_devices))
        .route("/devices/:device", get(get_instances))
        .nest(
            "/devices/:device",
            Router::new()
                .route("/instances", get(get_instances))
                .route("/instances/:instance", get(get_instance_attributes))
                .route(
                    "/instances/:instance/:attribute",
                    get(get_instance_attribute),
                ),
        );

    Router::new()
        .nest("/infiniband", ib_router)
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

async fn get_devices(State(state): State<Arc<dyn InstanceMetadataReader>>) -> (StatusCode, String) {
    let read_guard = state.read();
    let metadata = match read_guard.as_ref() {
        Some(metadata) => metadata,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata currently unavailable".to_string(),
            );
        }
    };

    let mut response = String::new();
    if let Some(devices) = &metadata.ib_devices {
        for (index, device) in devices.iter().enumerate() {
            response.push_str(&format!("{}={}\n", index, device.pf_guid));
        }

        (StatusCode::OK, response)
    } else {
        (StatusCode::NOT_FOUND, "devices not available".to_string())
    }
}

async fn get_instances(
    State(state): State<Arc<dyn InstanceMetadataReader>>,
    Path(device_index): Path<usize>,
) -> (StatusCode, String) {
    let read_guard = state.read();
    let metadata = match read_guard.as_ref() {
        Some(metadata) => metadata,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata currently unavailable".to_string(),
            );
        }
    };

    if let Some(devices) = &metadata.ib_devices {
        if devices.len() <= device_index {
            return (
                StatusCode::NOT_FOUND,
                format!("no device at index: {}", device_index),
            );
        }
        let dev = &devices[device_index];

        let mut response = String::new();
        for (index, instance) in dev.instances.iter().enumerate() {
            match &instance.ib_guid {
                Some(guid) => response.push_str(&format!("{}={}\n", index, guid)),
                None => continue,
            }
        }

        (StatusCode::OK, response)
    } else {
        (StatusCode::NOT_FOUND, "devices not available".to_string())
    }
}

async fn get_instance_attributes(
    State(state): State<Arc<dyn InstanceMetadataReader>>,
    Path((device_index, instance_index)): Path<(usize, usize)>,
) -> (StatusCode, String) {
    println!("Got here!");
    let read_guard = state.read();
    let metadata = match read_guard.as_ref() {
        Some(metadata) => metadata,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata currently unavailable".to_string(),
            );
        }
    };

    if let Some(devices) = &metadata.ib_devices {
        if devices.len() <= device_index {
            return (
                StatusCode::NOT_FOUND,
                format!("no device at index: {}", device_index),
            );
        }

        let dev = &devices[device_index];

        if dev.instances.len() <= instance_index {
            return (
                StatusCode::NOT_FOUND,
                format!("no instance at index: {}", instance_index),
            );
        }
        let inst = &dev.instances[instance_index];

        let mut response = String::new();

        if let Some(_ib_guid) = &inst.ib_guid {
            response += &(GUID.to_owned() + "\n")
        }
        if let Some(_ib_partition_id) = &inst.ib_partition_id {
            response += &(IB_PARTITION.to_owned() + "\n")
        }
        response.push_str(LID);

        (StatusCode::OK, response)
    } else {
        (StatusCode::NOT_FOUND, "devices not available".to_string())
    }
}

async fn get_instance_attribute(
    State(state): State<Arc<dyn InstanceMetadataReader>>,
    Path((device_index, instance_index, attribute)): Path<(usize, usize, String)>,
) -> (StatusCode, String) {
    let read_guard = state.read();
    let metadata = match read_guard.as_ref() {
        Some(metadata) => metadata,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata currently unavailable".to_string(),
            );
        }
    };

    if let Some(devices) = &metadata.ib_devices {
        if devices.len() <= device_index {
            return (
                StatusCode::NOT_FOUND,
                format!("no device at index: {}", device_index),
            );
        }
        let dev = &devices[device_index];

        if dev.instances.len() <= instance_index {
            return (
                StatusCode::NOT_FOUND,
                format!("no instance at index: {}", instance_index),
            );
        }
        let inst = &dev.instances[instance_index];

        return match attribute.as_str() {
            GUID => match &inst.ib_guid {
                Some(guid) => (StatusCode::OK, guid.clone()),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        format!("guid not found at index: {}", instance_index),
                    );
                }
            },
            IB_PARTITION => match &inst.ib_partition_id {
                Some(ib_partition_id) => (StatusCode::OK, ib_partition_id.to_string()),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        format!("ib partition not found at index: {}", instance_index),
                    );
                }
            },
            LID => (StatusCode::OK, inst.lid.to_string()),
            _ => (StatusCode::NOT_FOUND, "no such attribute".to_string()),
        };
    } else {
        (StatusCode::NOT_FOUND, "devices not available".to_string())
    }
}

#[cfg(test)]
mod tests {
    use axum::http;
    use rpc::Uuid;
    use uuid::uuid;

    use crate::instance_metadata_fetcher::{
        IBDeviceConfig, IBInstanceConfig, InstanceMetadata, MockInstanceMetadataReader,
    };

    use super::*;

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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        assert_eq!(body_str, expected_body);
    }

    #[tokio::test]
    async fn test_get_metadata_parameter_public_ipv4_category() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: None,
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
            ib_devices: None,
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
            ib_devices: None,
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
            "metadata currently unavailable",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_devices() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![
                IBDeviceConfig {
                    pf_guid: "pfguid1".to_string(),
                    instances: vec![IBInstanceConfig {
                        ib_partition_id: None,
                        ib_guid: Some("test-guid1".to_string()),
                        lid: 0,
                    }],
                },
                IBDeviceConfig {
                    pf_guid: "pfguid2".to_string(),
                    instances: vec![IBInstanceConfig {
                        ib_partition_id: None,
                        ib_guid: Some("test-guid2".to_string()),
                        lid: 1,
                    }],
                },
            ]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices",
            "0=pfguid1\n1=pfguid2\n",
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_incorrect_ib_device() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "pfguid1".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: None,
                    ib_guid: Some("test-guid1".to_string()),
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/2",
            "no device at index: 2",
            StatusCode::NOT_FOUND,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_instances() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![
                    IBInstanceConfig {
                        ib_partition_id: None,
                        ib_guid: Some("test-guid1".to_string()),
                        lid: 0,
                    },
                    IBInstanceConfig {
                        ib_partition_id: None,
                        ib_guid: Some("test-guid2".to_string()),
                        lid: 1,
                    },
                ],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances",
            "0=test-guid1\n1=test-guid2\n",
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_instance() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: Some(Uuid::from(uuid!(
                        "67e55044-10b1-426f-9247-bb680e5fe0c8"
                    ))),
                    ib_guid: Some("test-guid1".to_string()),
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances/0",
            "guid\npartition\nlid",
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_instance_not_all_attributes() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: None,
                    ib_guid: None,
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances/0",
            "lid",
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_incorrect_ib_instance() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: None,
                    ib_guid: Some("test-guid1".to_string()),
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances/3",
            "no instance at index: 3",
            StatusCode::NOT_FOUND,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_instance_attribute() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: None,
                    ib_guid: Some("test-guid".to_string()),
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances/0/guid",
            "test-guid",
            StatusCode::OK,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn test_get_ib_instance_nonexistent_attribute() {
        let metadata = InstanceMetadata {
            address: "127.0.0.1".to_string(),
            hostname: "localhost".to_string(),
            user_data: "\"userData\": {\"data\": 0}".to_string(),
            ib_devices: Some(vec![IBDeviceConfig {
                pf_guid: "guid".to_string(),
                instances: vec![IBInstanceConfig {
                    ib_partition_id: None,
                    ib_guid: None,
                    lid: 0,
                }],
            }]),
        };

        let (server, server_port) = setup_server(Some(metadata.clone())).await;
        send_request_and_check_response(
            server_port,
            "infiniband/devices/0/instances/0/partition",
            "ib partition not found at index: 0",
            StatusCode::NOT_FOUND,
        )
        .await;
        server.abort();
    }
}
