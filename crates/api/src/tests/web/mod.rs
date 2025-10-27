use axum::Router;
use common::api_fixtures::TestEnv;
use hyper::http::Request;
use hyper::http::request::Builder;

use crate::tests::common;
use crate::web::routes;
mod machine_health;
mod managed_host;

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
