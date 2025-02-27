use crate::logging::service_health_metrics::{
    ServiceHealthContext, start_export_service_health_metrics,
};
use crate::resource_pool::ResourcePoolStats;
use crate::tests::common::prometheus_text_parser::ParsedPrometheusMetrics;
use crate::tests::common::test_meter::TestMeter;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[crate::sqlx_test]
async fn test_service_health_metrics(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let test_meter = TestMeter::default();
    let context = ServiceHealthContext {
        meter: test_meter.meter(),
        database_pool: pool,
        resource_pool_stats: Arc::new(Mutex::new(HashMap::from([
            (
                "pool1".to_string(),
                ResourcePoolStats { used: 10, free: 20 },
            ),
            (
                "pool2".to_string(),
                ResourcePoolStats { used: 20, free: 10 },
            ),
        ]))),
    };
    start_export_service_health_metrics(context);

    let expected_metrics = include_str!("metrics_fixtures/test_service_health_metrics.txt")
        .parse::<ParsedPrometheusMetrics>()
        .unwrap()
        .scrub_build_attributes();
    let metrics = test_meter
        .export_metrics()
        .parse::<ParsedPrometheusMetrics>()
        .unwrap()
        .scrub_build_attributes();

    assert_eq!(expected_metrics, metrics);

    Ok(())
}
