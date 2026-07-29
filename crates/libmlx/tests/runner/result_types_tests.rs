/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// tests/result_types_tests.rs
// Tests for result types and their functionality

use std::time::Duration;

use libmlx::runner::result_types::{QueriedVariable, QueryResult, SyncResult};

use super::common;

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn test_queried_variable_serialization() {
        let registry = common::create_test_registry();
        let sriov_var = registry.get_variable("SRIOV_EN").unwrap().clone();

        let queried_var = QueriedVariable {
            variable: sriov_var.clone(),
            current_value: sriov_var.with(true).unwrap(),
            default_value: sriov_var.with(false).unwrap(),
            next_value: sriov_var.with(true).unwrap(),
            modified: true,
            read_only: false,
        };

        // Should be able to serialize and deserialize
        let json = serde_json::to_string(&queried_var).unwrap();
        let deserialized: QueriedVariable = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name(), "SRIOV_EN");
        assert!(deserialized.modified);
        assert!(!deserialized.read_only);
    }

    #[test]
    fn test_sync_result_serialization() {
        let device_info = common::create_test_device_info();
        let query_result = QueryResult {
            device_info,
            variables: vec![],
        };

        let sync_result = SyncResult {
            variables_checked: 3,
            variables_changed: 1,
            changes_applied: vec![],
            execution_time: Duration::from_millis(200),
            query_result,
        };

        let json = serde_json::to_string(&sync_result).unwrap();
        let deserialized: SyncResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.variables_checked, 3);
        assert_eq!(deserialized.variables_changed, 1);
        // Note: execution_time is skipped in serialization due to #[serde(skip)]
    }
}
