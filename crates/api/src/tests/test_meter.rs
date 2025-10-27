/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use common::test_meter::TestMeter;
use opentelemetry::KeyValue;

use crate::tests::common;

#[test]
fn test_test_meter() {
    let test_meter = TestMeter::default();

    let meter = test_meter.meter();

    let a = meter.u64_counter("a").build();
    let b = meter.u64_counter("b").build();
    let c = meter.u64_histogram("c").with_unit("s").build();

    a.add(123, &[]);
    let attrs = &[KeyValue::new("attr1", "abc"), KeyValue::new("attr2", "def")];
    b.add(543, attrs);
    c.record(20, &[]);

    assert_eq!(test_meter.formatted_metric("a_total").unwrap(), "123");
    assert_eq!(
        test_meter.formatted_metrics("a_total"),
        vec!["123".to_string()]
    );
    assert_eq!(
        test_meter.formatted_metrics("b_total"),
        vec!["{attr1=\"abc\",attr2=\"def\"} 543".to_string()]
    );
    assert_eq!(
        test_meter.formatted_metrics("c_seconds_count"),
        vec!["1".to_string()]
    );
    assert!(
        test_meter
            .formatted_metrics("c_seconds_bucket")
            .contains(&"{le=\"100\"} 1".to_string())
    );

    assert_eq!(
        test_meter.parsed_metrics("a_total"),
        vec![("".to_string(), "123".to_string())]
    );
    assert_eq!(
        test_meter.parsed_metrics("b_total"),
        vec![(
            "{attr1=\"abc\",attr2=\"def\"}".to_string(),
            "543".to_string()
        )]
    );
    assert_eq!(
        test_meter.parsed_metrics("c_seconds_count"),
        vec![("".to_string(), "1".to_string())]
    );
    let c_buckets = test_meter.parsed_metrics("c_seconds_bucket");
    assert!(c_buckets.contains(&("{le=\"+Inf\"}".to_string(), "1".to_string())));
    assert!(c_buckets.contains(&("{le=\"50\"}".to_string(), "1".to_string())));
    assert!(c_buckets.contains(&("{le=\"10\"}".to_string(), "0".to_string())));
    assert!(c_buckets.contains(&("{le=\"0\"}".to_string(), "0".to_string())));
}
