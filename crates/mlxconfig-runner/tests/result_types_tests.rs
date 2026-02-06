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

use mlxconfig_runner::{
    ComparisonResult, PlannedChange, QueriedDeviceInfo, QueriedVariable, QueryResult, SyncResult,
    VariableChange,
};
use mlxconfig_variables::MlxValueType;

mod common;

#[test]
fn test_queried_variable_construction() {
    let registry = common::create_test_registry();
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap().clone();

    let current_value = sriov_var.with(true).unwrap();
    let default_value = sriov_var.with(false).unwrap();
    let next_value = sriov_var.with(true).unwrap();

    let queried_var = QueriedVariable::new(
        sriov_var.clone(),
        current_value,
        default_value,
        next_value,
        true,  // modified
        false, // read_only
    );

    assert_eq!(queried_var.name(), "SRIOV_EN");
    assert_eq!(
        queried_var.description(),
        "Enable Single-Root I/O Virtualization"
    );
    assert!(queried_var.modified);
    assert!(!queried_var.read_only);
}

#[test]
fn test_queried_variable_pending_change_detection() {
    let registry = common::create_test_registry();
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap().clone();

    // Test case where current != next (pending change)
    let current_value = sriov_var.with(false).unwrap();
    let default_value = sriov_var.with(false).unwrap();
    let next_value = sriov_var.with(true).unwrap();

    let queried_var_with_pending = QueriedVariable::new(
        sriov_var.clone(),
        current_value,
        default_value,
        next_value,
        true,
        false,
    );

    assert!(queried_var_with_pending.is_pending_change());

    // Test case where current == next (no pending change)
    let current_value = sriov_var.with(true).unwrap();
    let next_value = sriov_var.with(true).unwrap();
    let default_value = sriov_var.with(false).unwrap();

    let queried_var_no_pending = QueriedVariable::new(
        sriov_var,
        current_value,
        default_value,
        next_value,
        true,
        false,
    );

    assert!(!queried_var_no_pending.is_pending_change());
}

#[test]
fn test_query_result_construction() {
    let device_info = common::create_test_device_info();
    let registry = common::create_test_registry();

    // Create some test variables
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap().clone();
    let vfs_var = registry.get_variable("NUM_OF_VFS").unwrap().clone();

    let sriov_queried = QueriedVariable::new(
        sriov_var.clone(),
        sriov_var.with(true).unwrap(),
        sriov_var.with(false).unwrap(),
        sriov_var.with(true).unwrap(),
        true,
        false,
    );

    let vfs_queried = QueriedVariable::new(
        vfs_var.clone(),
        vfs_var.with(16i64).unwrap(),
        vfs_var.with(8i64).unwrap(),
        vfs_var.with(16i64).unwrap(),
        true,
        false,
    );

    let variables = vec![sriov_queried, vfs_queried];
    let query_result = QueryResult::new(device_info, variables);

    assert_eq!(query_result.variable_count(), 2);
    assert_eq!(
        query_result.device_info.device_type,
        Some("BlueField3".to_string())
    );

    let var_names = query_result.variable_names();
    assert!(var_names.contains(&"SRIOV_EN"));
    assert!(var_names.contains(&"NUM_OF_VFS"));

    // Test get_variable
    let sriov_result = query_result.get_variable("SRIOV_EN");
    assert!(sriov_result.is_some());
    assert_eq!(sriov_result.unwrap().name(), "SRIOV_EN");

    let nonexistent = query_result.get_variable("NONEXISTENT");
    assert!(nonexistent.is_none());
}

#[test]
fn test_sync_result_construction() {
    let device_info = common::create_test_device_info();
    let query_result = QueryResult::new(device_info, vec![]);
    let registry = common::create_test_registry();

    // Create proper MlxConfigValue instances for VariableChange
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let vfs_var = registry.get_variable("NUM_OF_VFS").unwrap();

    let changes = vec![
        VariableChange::new(
            "SRIOV_EN".to_string(),
            sriov_var.with(false).unwrap(),
            sriov_var.with(true).unwrap(),
        ),
        VariableChange::new(
            "NUM_OF_VFS".to_string(),
            vfs_var.with(8i64).unwrap(),
            vfs_var.with(16i64).unwrap(),
        ),
    ];

    let sync_result = SyncResult::new(
        5, // variables_checked
        2, // variables_changed
        changes,
        Duration::from_millis(500),
        query_result,
    );

    assert_eq!(sync_result.variables_checked, 5);
    assert_eq!(sync_result.variables_changed, 2);
    assert_eq!(sync_result.changes_applied.len(), 2);
    assert_eq!(sync_result.execution_time, Duration::from_millis(500));

    let summary = sync_result.summary();
    assert!(summary.contains("2/5"));
    assert!(summary.contains("500ms"));
}

#[test]
fn test_comparison_result_construction() {
    let device_info = common::create_test_device_info();
    let query_result = QueryResult::new(device_info, vec![]);
    let registry = common::create_test_registry();

    // Create proper MlxConfigValue instances for PlannedChange
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let power_var = registry.get_variable("POWER_MODE").unwrap();

    let planned_changes = vec![
        PlannedChange::new(
            "SRIOV_EN".to_string(),
            sriov_var.with(false).unwrap(),
            sriov_var.with(true).unwrap(),
        ),
        PlannedChange::new(
            "POWER_MODE".to_string(),
            power_var.with("LOW").unwrap(),
            power_var.with("HIGH").unwrap(),
        ),
    ];

    let comparison_result = ComparisonResult::new(
        3, // variables_checked
        2, // variables_needing_change
        planned_changes,
        query_result,
    );

    assert_eq!(comparison_result.variables_checked, 3);
    assert_eq!(comparison_result.variables_needing_change, 2);
    assert_eq!(comparison_result.planned_changes.len(), 2);

    let summary = comparison_result.summary();
    assert!(summary.contains("2/3"));
    assert!(summary.contains("would change"));
}

#[test]
fn test_planned_change_description() {
    let registry = common::create_test_registry();
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();

    let planned_change = PlannedChange::new(
        "SRIOV_EN".to_string(),
        sriov_var.with(false).unwrap(),
        sriov_var.with(true).unwrap(),
    );

    let description = planned_change.description();
    assert!(description.contains("SRIOV_EN"));
    assert!(description.contains("false"));
    assert!(description.contains("true"));
    assert!(description.contains("→"));
}

#[test]
fn test_variable_change_description() {
    let registry = common::create_test_registry();
    let vfs_var = registry.get_variable("NUM_OF_VFS").unwrap();

    let variable_change = VariableChange::new(
        "NUM_OF_VFS".to_string(),
        vfs_var.with(8i64).unwrap(),
        vfs_var.with(16i64).unwrap(),
    );

    let description = variable_change.description();
    assert!(description.contains("NUM_OF_VFS"));
    assert!(description.contains("8"));
    assert!(description.contains("16"));
    assert!(description.contains("→"));
}

#[test]
fn test_query_result_empty() {
    let device_info = QueriedDeviceInfo::new();
    let query_result = QueryResult::new(device_info, vec![]);

    assert_eq!(query_result.variable_count(), 0);
    assert!(query_result.variable_names().is_empty());
    assert!(query_result.get_variable("ANY_VAR").is_none());
}

#[test]
fn test_sync_result_no_changes() {
    let device_info = common::create_test_device_info();
    let query_result = QueryResult::new(device_info, vec![]);

    let sync_result = SyncResult::new(
        5,      // variables_checked
        0,      // variables_changed
        vec![], // no changes
        Duration::from_millis(100),
        query_result,
    );

    assert_eq!(sync_result.variables_checked, 5);
    assert_eq!(sync_result.variables_changed, 0);
    assert!(sync_result.changes_applied.is_empty());

    let summary = sync_result.summary();
    assert!(summary.contains("0/5"));
}

#[test]
fn test_comparison_result_no_changes_needed() {
    let device_info = common::create_test_device_info();
    let query_result = QueryResult::new(device_info, vec![]);

    let comparison_result = ComparisonResult::new(
        5,      // variables_checked
        0,      // variables_needing_change
        vec![], // no planned changes
        query_result,
    );

    assert_eq!(comparison_result.variables_checked, 5);
    assert_eq!(comparison_result.variables_needing_change, 0);
    assert!(comparison_result.planned_changes.is_empty());

    let summary = comparison_result.summary();
    assert!(summary.contains("0/5"));
}

#[test]
fn test_array_values_in_results() {
    let registry = common::create_test_registry();
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap().clone();

    let current_array = gpio_var.with(vec![true, false, true, false]).unwrap();
    let default_array = gpio_var.with(vec![false, false, false, false]).unwrap();
    let next_array = gpio_var.with(vec![true, false, true, false]).unwrap();

    let gpio_queried = QueriedVariable::new(
        gpio_var,
        current_array,
        default_array,
        next_array,
        true,
        false,
    );

    assert_eq!(gpio_queried.name(), "GPIO_ENABLED");

    // Verify array values
    if let MlxValueType::BooleanArray(values) = &gpio_queried.current_value.value {
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], Some(false));
        assert_eq!(values[2], Some(true));
        assert_eq!(values[3], Some(false));
    } else {
        panic!("Expected BooleanArray");
    }
}

#[test]
fn test_enum_values_in_planned_changes() {
    let registry = common::create_test_registry();
    let gpio_modes_var = registry.get_variable("GPIO_MODES").unwrap();

    // Create a single-element sparse array for index 0
    let input_sparse = vec![Some("input".to_string())];
    let output_sparse = vec![Some("output".to_string())];

    // Pad to full array size (8 elements) with None values
    let mut input_full = input_sparse;
    input_full.resize(8, None);
    let mut output_full = output_sparse;
    output_full.resize(8, None);

    let planned_change = PlannedChange::new(
        "GPIO_MODES[0]".to_string(),
        gpio_modes_var.with(input_full).unwrap(),
        gpio_modes_var.with(output_full).unwrap(),
    );

    let description = planned_change.description();
    assert!(description.contains("GPIO_MODES[0]"));
    // The description will show the array format, not just the individual values
    assert!(description.contains("input"));
    assert!(description.contains("output"));
}

#[test]
fn test_preset_values_in_variable_changes() {
    let registry = common::create_test_registry();
    let preset_var = registry.get_variable("PERFORMANCE_PRESET").unwrap();

    let variable_change = VariableChange::new(
        "PERFORMANCE_PRESET".to_string(),
        preset_var.with(3u8).unwrap(),
        preset_var.with(7u8).unwrap(),
    );

    let description = variable_change.description();
    assert!(description.contains("PERFORMANCE_PRESET"));
    assert!(description.contains("preset_3"));
    assert!(description.contains("preset_7"));
}

#[test]
fn test_device_info_in_query_result() {
    let device_info = QueriedDeviceInfo::new()
        .with_device_id("01:00.0")
        .with_device_type("BlueField3")
        .with_part_number("MCX713106AS-VDAT");

    let query_result = QueryResult::new(device_info, vec![]);

    assert_eq!(
        query_result.device_info.device_id,
        Some("01:00.0".to_string())
    );
    assert_eq!(
        query_result.device_info.device_type,
        Some("BlueField3".to_string())
    );
    assert_eq!(
        query_result.device_info.part_number,
        Some("MCX713106AS-VDAT".to_string())
    );
}

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn test_queried_variable_serialization() {
        let registry = common::create_test_registry();
        let sriov_var = registry.get_variable("SRIOV_EN").unwrap().clone();

        let queried_var = QueriedVariable::new(
            sriov_var.clone(),
            sriov_var.with(true).unwrap(),
            sriov_var.with(false).unwrap(),
            sriov_var.with(true).unwrap(),
            true,
            false,
        );

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
        let query_result = QueryResult::new(device_info, vec![]);

        let sync_result = SyncResult::new(3, 1, vec![], Duration::from_millis(200), query_result);

        let json = serde_json::to_string(&sync_result).unwrap();
        let deserialized: SyncResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.variables_checked, 3);
        assert_eq!(deserialized.variables_changed, 1);
        // Note: execution_time is skipped in serialization due to #[serde(skip)]
    }
}
