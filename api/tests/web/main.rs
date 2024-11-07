use axum::Router;
use carbide::web::routes;
use common::api_fixtures::TestEnv;
use hyper::http::{request::Builder, Request};

#[path = "../common/mod.rs"]
pub mod common;
mod managed_host;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

fn make_test_app(env: &TestEnv) -> Router {
    let r = routes(env.api.clone()).unwrap();
    Router::new().nest_service("/admin", r)
}

fn authenticated_request_builder() -> Builder {
    // admin:Welcome123
    Request::builder()
        .header("Host", "with.the.most")
        .header("Authorization", "Basic YWRtaW46V2VsY29tZTEyMw==")
}
