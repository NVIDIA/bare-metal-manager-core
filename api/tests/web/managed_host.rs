use axum::body::Body;
use http::StatusCode;
use hyper::body::HttpBody;
use tower::ServiceExt;
use utils::ManagedHostOutput;

use crate::{
    authenticated_request_builder,
    common::api_fixtures::{create_test_env, managed_host::create_managed_host_multi_dpu},
    make_test_app,
};

#[sqlx::test(fixtures(
    path = "../fixtures",
    scripts("create_domain", "create_vpc", "create_network_segment")
))]
async fn test_ok(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let app = make_test_app(&env);
    _ = create_managed_host_multi_dpu(&env, 1).await;

    let response = app
        .oneshot(
            authenticated_request_builder()
                .uri("/admin/managed-host.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Empty response body?")
        .to_bytes();

    let body_str = std::str::from_utf8(&body_bytes).expect("Invalid UTF-8 in body");
    let hosts: Vec<ManagedHostOutput> =
        serde_json::from_str(body_str).expect("Could not deserialize response");

    assert_eq!(hosts.len(), 1, "One host should have been returned");
    let host = hosts.first().unwrap();
    assert_eq!(host.dpus.len(), 1, "Host should have 1 dpu");
    let dpu = host.dpus.first().unwrap();
    assert_ne!(
        dpu.machine_id, host.machine_id,
        "DPU should not have the same machine ID as the host"
    );
}

#[sqlx::test(fixtures(
    path = "../fixtures",
    scripts("create_domain", "create_vpc", "create_network_segment")
))]
async fn test_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let app = make_test_app(&env);
    let managed_host_id = create_managed_host_multi_dpu(&env, 2).await;

    let response = app
        .oneshot(
            authenticated_request_builder()
                .uri("/admin/managed-host.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Empty response body?")
        .to_bytes();

    let body_str = std::str::from_utf8(&body_bytes).expect("Invalid UTF-8 in body");
    let hosts: Vec<ManagedHostOutput> =
        serde_json::from_str(body_str).expect("Could not deserialize response");

    assert!(
        !hosts.is_empty(),
        "At least one host should have been returned"
    );
    let host = hosts
        .into_iter()
        .find(|h| {
            h.machine_id
                .as_ref()
                .map(|m| m == &managed_host_id.to_string())
                .unwrap_or(false)
        })
        .unwrap_or_else(|| {
            panic!(
                "Could not find expected host {} in managed_hosts output",
                managed_host_id
            )
        });
    assert!(host.hostname.is_some(), "Hostname should be set");
    assert_eq!(host.dpus.len(), 2, "Host should have 2 dpus");
    for dpu in host.dpus.iter() {
        assert_ne!(
            dpu.machine_id, host.machine_id,
            "DPU should not have the same machine ID as the host"
        );
    }
}
