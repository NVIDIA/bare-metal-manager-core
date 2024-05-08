use axum::Router;
use carbide::web::routes;
use common::api_fixtures::TestEnv;
use http::{request::Builder, Request};

#[path = "../common/mod.rs"]
pub mod common;
mod managed_host;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

fn make_test_app(env: &TestEnv) -> Router {
    Router::new().nest_service("/admin", routes(env.api.clone()))
}

fn authenticated_request_builder() -> Builder {
    // admin:Welcome123
    Request::builder().header("Authorization", "Basic YWRtaW46V2VsY29tZTEyMw==")
}
