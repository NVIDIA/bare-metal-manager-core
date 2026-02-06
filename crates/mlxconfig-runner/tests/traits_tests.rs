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

// tests/traits_tests.rs
// Tests for MlxConfigSettable and MlxConfigQueryable traits

use mlxconfig_runner::{MlxConfigQueryable, MlxConfigSettable, traits};
use mlxconfig_variables::MlxValueType;

mod common;

#[test]
fn test_mlx_config_settable_vec_config_value() {
    let registry = common::create_test_registry();
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let config_value = sriov_var.with(true).unwrap();

    let config_values = vec![config_value.clone()];
    let result = config_values.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name(), "SRIOV_EN");
    assert_eq!(result[0].value, MlxValueType::Boolean(true));
}

#[test]
fn test_mlx_config_settable_string_tuples() {
    let registry = common::create_test_registry();

    let assignments = &[
        ("SRIOV_EN", "true"),
        ("NUM_OF_VFS", "16"),
        ("POWER_MODE", "HIGH"),
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 3);

    // Find each variable and verify
    let sriov = result.iter().find(|v| v.name() == "SRIOV_EN").unwrap();
    assert_eq!(sriov.value, MlxValueType::Boolean(true));

    let vfs = result.iter().find(|v| v.name() == "NUM_OF_VFS").unwrap();
    assert_eq!(vfs.value, MlxValueType::Integer(16));

    let power = result.iter().find(|v| v.name() == "POWER_MODE").unwrap();
    assert_eq!(power.value, MlxValueType::Enum("HIGH".to_string()));
}

#[test]
fn test_mlx_config_settable_arrays_direct() {
    let registry = common::create_test_registry();

    // Test that we can pass arrays directly without needing as &[_]
    let assignments = [
        ("SRIOV_EN", "true"),
        ("NUM_OF_VFS", "16"),
        ("POWER_MODE", "HIGH"),
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 3);

    // Find each variable and verify
    let sriov = result.iter().find(|v| v.name() == "SRIOV_EN").unwrap();
    assert_eq!(sriov.value, MlxValueType::Boolean(true));

    let vfs = result.iter().find(|v| v.name() == "NUM_OF_VFS").unwrap();
    assert_eq!(vfs.value, MlxValueType::Integer(16));

    let power = result.iter().find(|v| v.name() == "POWER_MODE").unwrap();
    assert_eq!(power.value, MlxValueType::Enum("HIGH".to_string()));
}

#[test]
fn test_mlx_config_settable_array_references() {
    let registry = common::create_test_registry();

    // Test that array references also work
    let assignments = &[("SRIOV_EN", "false"), ("NUM_OF_VFS", "32")];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 2);

    let sriov = result.iter().find(|v| v.name() == "SRIOV_EN").unwrap();
    assert_eq!(sriov.value, MlxValueType::Boolean(false));

    let vfs = result.iter().find(|v| v.name() == "NUM_OF_VFS").unwrap();
    assert_eq!(vfs.value, MlxValueType::Integer(32));
}

#[test]
fn test_mlx_config_settable_different_array_sizes() {
    let registry = common::create_test_registry();

    // Test single element array
    let single = [("SRIOV_EN", "true")];
    let result = single.to_config_values(&registry).unwrap();
    assert_eq!(result.len(), 1);

    // Test larger arrays
    let large = [
        ("SRIOV_EN", "true"),
        ("NUM_OF_VFS", "16"),
        ("POWER_MODE", "HIGH"),
        ("PERFORMANCE_PRESET", "5"),
        ("DEVICE_NAME", "test-device"),
    ];
    let result = large.to_config_values(&registry).unwrap();
    assert_eq!(result.len(), 5);
}

#[test]
fn test_mlx_config_settable_arrays_with_indices() {
    let registry = common::create_test_registry();

    // Test that array index syntax works with direct arrays
    let assignments = [
        ("GPIO_ENABLED[0]", "true"),
        ("GPIO_ENABLED[2]", "false"),
        ("GPIO_MODES[1]", "output"),
        ("GPIO_MODES[3]", "bidirectional"),
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 2); // Two arrays: GPIO_ENABLED and GPIO_MODES

    // Find GPIO_ENABLED array
    let gpio_enabled = result.iter().find(|v| v.name() == "GPIO_ENABLED").unwrap();
    if let MlxValueType::BooleanArray(values) = &gpio_enabled.value {
        assert_eq!(values.len(), 4); // Array size from registry spec
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], None); // Not set in assignments
        assert_eq!(values[2], Some(false));
        assert_eq!(values[3], None); // Not set in assignments
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }

    // Find GPIO_MODES array
    let gpio_modes = result.iter().find(|v| v.name() == "GPIO_MODES").unwrap();
    if let MlxValueType::EnumArray(values) = &gpio_modes.value {
        assert_eq!(values.len(), 8); // Array size from registry spec
        assert_eq!(values[0], None);
        assert_eq!(values[1], Some("output".to_string()));
        assert_eq!(values[2], None);
        assert_eq!(values[3], Some("bidirectional".to_string()));
        assert!(values[4..8].iter().all(|v| v.is_none()));
    } else {
        panic!("Expected EnumArray for GPIO_MODES");
    }
}

#[test]
fn test_mlx_config_settable_vec_string_tuples() {
    let registry = common::create_test_registry();

    let assignments = vec![
        ("SRIOV_EN".to_string(), "false".to_string()),
        ("NUM_OF_VFS".to_string(), "32".to_string()),
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 2);

    let sriov = result.iter().find(|v| v.name() == "SRIOV_EN").unwrap();
    assert_eq!(sriov.value, MlxValueType::Boolean(false));

    let vfs = result.iter().find(|v| v.name() == "NUM_OF_VFS").unwrap();
    assert_eq!(vfs.value, MlxValueType::Integer(32));
}

#[test]
fn test_mlx_config_settable_array_indices() {
    let registry = common::create_test_registry();

    let assignments = &[
        ("GPIO_ENABLED[0]", "true"),
        ("GPIO_ENABLED[2]", "false"),
        ("GPIO_MODES[1]", "output"),
        ("GPIO_MODES[3]", "bidirectional"),
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    assert_eq!(result.len(), 2); // Two arrays: GPIO_ENABLED and GPIO_MODES

    // Find GPIO_ENABLED array
    let gpio_enabled = result.iter().find(|v| v.name() == "GPIO_ENABLED").unwrap();
    if let MlxValueType::BooleanArray(values) = &gpio_enabled.value {
        assert_eq!(values.len(), 4); // Array size from registry spec
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], None); // Not set in assignments
        assert_eq!(values[2], Some(false));
        assert_eq!(values[3], None); // Not set in assignments
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }

    // Find GPIO_MODES array
    let gpio_modes = result.iter().find(|v| v.name() == "GPIO_MODES").unwrap();
    if let MlxValueType::EnumArray(values) = &gpio_modes.value {
        assert_eq!(values.len(), 8); // Array size from registry spec
        assert_eq!(values[0], None);
        assert_eq!(values[1], Some("output".to_string()));
        assert_eq!(values[2], None);
        assert_eq!(values[3], Some("bidirectional".to_string()));
        assert!(values[4..8].iter().all(|v| v.is_none()));
    } else {
        panic!("Expected EnumArray for GPIO_MODES");
    }
}

#[test]
fn test_mlx_config_settable_variable_not_found() {
    let registry = common::create_test_registry();

    let assignments = &[("NONEXISTENT_VAR", "value")];

    let result = assignments.to_config_values(&registry);
    assert!(result.is_err());

    if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_VAR");
    } else {
        panic!("Expected VariableNotFound error");
    }
}

#[test]
fn test_mlx_config_queryable_string_slice() {
    let registry = common::create_test_registry();

    let variables = &["SRIOV_EN", "NUM_OF_VFS", "POWER_MODE"];
    let result = variables.to_variable_names(&registry).unwrap();

    assert_eq!(result.len(), 3);
    assert!(result.contains(&"SRIOV_EN".to_string()));
    assert!(result.contains(&"NUM_OF_VFS".to_string()));
    assert!(result.contains(&"POWER_MODE".to_string()));
}

#[test]
fn test_mlx_config_queryable_arrays_direct() {
    let registry = common::create_test_registry();

    // Test that we can pass arrays directly without needing as &[_]
    let variables = ["SRIOV_EN", "NUM_OF_VFS", "POWER_MODE"];
    let result = variables.to_variable_names(&registry).unwrap();

    assert_eq!(result.len(), 3);
    assert!(result.contains(&"SRIOV_EN".to_string()));
    assert!(result.contains(&"NUM_OF_VFS".to_string()));
    assert!(result.contains(&"POWER_MODE".to_string()));
}

#[test]
fn test_mlx_config_queryable_array_references() {
    let registry = common::create_test_registry();

    // Test that array references also work
    let variables = &["GPIO_ENABLED", "THERMAL_SENSORS"];
    let result = variables.to_variable_names(&registry).unwrap();

    // GPIO_ENABLED has size 4, THERMAL_SENSORS has size 6
    assert_eq!(result.len(), 10); // 4 + 6

    // Check that array expansion works
    assert!(result.contains(&"GPIO_ENABLED[0]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[5]".to_string()));
}

#[test]
fn test_mlx_config_queryable_different_array_sizes() {
    let registry = common::create_test_registry();

    // Test single element array
    let single = ["SRIOV_EN"];
    let result = single.to_variable_names(&registry).unwrap();
    assert_eq!(result.len(), 1);
    assert!(result.contains(&"SRIOV_EN".to_string()));

    // Test larger arrays
    let large = ["SRIOV_EN", "NUM_OF_VFS", "POWER_MODE", "DEVICE_NAME"];
    let result = large.to_variable_names(&registry).unwrap();
    assert_eq!(result.len(), 4);
    assert!(result.contains(&"SRIOV_EN".to_string()));
    assert!(result.contains(&"NUM_OF_VFS".to_string()));
    assert!(result.contains(&"POWER_MODE".to_string()));
    assert!(result.contains(&"DEVICE_NAME".to_string()));
}

#[test]
fn test_mlx_config_queryable_vec_string() {
    let registry = common::create_test_registry();

    let variables = vec!["SRIOV_EN".to_string(), "DEVICE_NAME".to_string()];
    let result = variables.to_variable_names(&registry).unwrap();

    assert_eq!(result.len(), 2);
    assert!(result.contains(&"SRIOV_EN".to_string()));
    assert!(result.contains(&"DEVICE_NAME".to_string()));
}

#[test]
fn test_mlx_config_queryable_array_expansion() {
    let registry = common::create_test_registry();

    let variables = &["GPIO_ENABLED", "THERMAL_SENSORS"];
    let result = variables.to_variable_names(&registry).unwrap();

    // GPIO_ENABLED has size 4, THERMAL_SENSORS has size 6
    assert_eq!(result.len(), 10); // 4 + 6

    // Check GPIO_ENABLED indices
    assert!(result.contains(&"GPIO_ENABLED[0]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[1]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[2]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[3]".to_string()));

    // Check THERMAL_SENSORS indices
    assert!(result.contains(&"THERMAL_SENSORS[0]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[1]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[2]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[3]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[4]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[5]".to_string()));
}

#[test]
fn test_mlx_config_queryable_variable_not_found() {
    let registry = common::create_test_registry();

    let variables = &["SRIOV_EN", "NONEXISTENT_VAR"];
    let result = variables.to_variable_names(&registry);

    assert!(result.is_err());
    if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_VAR");
    } else {
        panic!("Expected VariableNotFound error");
    }
}

#[test]
fn test_mlx_config_queryable_vec_variables() {
    let registry = common::create_test_registry();

    let variables = vec![
        registry.get_variable("SRIOV_EN").unwrap().clone(),
        registry.get_variable("NUM_OF_VFS").unwrap().clone(),
    ];

    let result = variables.to_variable_names(&registry).unwrap();

    assert_eq!(result.len(), 2);
    assert!(result.contains(&"SRIOV_EN".to_string()));
    assert!(result.contains(&"NUM_OF_VFS".to_string()));
}

#[test]
fn test_parse_array_index() {
    // Test valid array index formats
    let result = traits::parse_array_index("ARRAY_VAR[0]").unwrap();
    assert_eq!(result, Some(("ARRAY_VAR".to_string(), 0)));

    let result = traits::parse_array_index("GPIO_ENABLED[15]").unwrap();
    assert_eq!(result, Some(("GPIO_ENABLED".to_string(), 15)));

    let result = traits::parse_array_index("COMPLEX_ARRAY_NAME[999]").unwrap();
    assert_eq!(result, Some(("COMPLEX_ARRAY_NAME".to_string(), 999)));

    // Test non-array format
    let result = traits::parse_array_index("SRIOV_EN").unwrap();
    assert_eq!(result, None);

    let result = traits::parse_array_index("POWER_MODE").unwrap();
    assert_eq!(result, None);

    // Test invalid formats
    let result = traits::parse_array_index("INVALID[]");
    assert!(result.is_err());

    let result = traits::parse_array_index("invalid[0]");
    assert!(result.unwrap().is_none());

    let result = traits::parse_array_index("VAR[not_a_number]");
    assert!(result.is_err());
}

#[test]
fn test_expand_variable_for_query() {
    let registry = common::create_test_registry();

    // Test scalar variable expansion
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let result = traits::expand_variable_for_query(sriov_var);
    assert_eq!(result, vec!["SRIOV_EN".to_string()]);

    // Test boolean array expansion
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap();
    let result = traits::expand_variable_for_query(gpio_var);
    assert_eq!(
        result,
        vec![
            "GPIO_ENABLED[0]".to_string(),
            "GPIO_ENABLED[1]".to_string(),
            "GPIO_ENABLED[2]".to_string(),
            "GPIO_ENABLED[3]".to_string(),
        ]
    );

    // Test integer array expansion
    let thermal_var = registry.get_variable("THERMAL_SENSORS").unwrap();
    let result = traits::expand_variable_for_query(thermal_var);
    assert_eq!(
        result,
        vec![
            "THERMAL_SENSORS[0]".to_string(),
            "THERMAL_SENSORS[1]".to_string(),
            "THERMAL_SENSORS[2]".to_string(),
            "THERMAL_SENSORS[3]".to_string(),
            "THERMAL_SENSORS[4]".to_string(),
            "THERMAL_SENSORS[5]".to_string(),
        ]
    );

    // Test enum array expansion
    let gpio_modes_var = registry.get_variable("GPIO_MODES").unwrap();
    let result = traits::expand_variable_for_query(gpio_modes_var);
    assert_eq!(result.len(), 8); // Size 8 from registry
    assert_eq!(result[0], "GPIO_MODES[0]".to_string());
    assert_eq!(result[7], "GPIO_MODES[7]".to_string());
}

#[test]
fn test_build_sparse_array_value_boolean() {
    let registry = common::create_test_registry();
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap();

    let indices = vec![(0, true), (2, false)];
    let result = traits::build_sparse_array_value(gpio_var, indices).unwrap();

    if let MlxValueType::BooleanArray(values) = &result.value {
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], None);
        assert_eq!(values[2], Some(false));
        assert_eq!(values[3], None);
    } else {
        panic!("Expected BooleanArray");
    }
}

#[test]
fn test_build_sparse_array_value_integer() {
    let registry = common::create_test_registry();
    let thermal_var = registry.get_variable("THERMAL_SENSORS").unwrap();

    let indices = vec![(1, 42i64), (3, 38i64), (5, 40i64)];
    let result = traits::build_sparse_array_value(thermal_var, indices).unwrap();

    if let MlxValueType::IntegerArray(values) = &result.value {
        assert_eq!(values.len(), 6);
        assert_eq!(values[0], None);
        assert_eq!(values[1], Some(42));
        assert_eq!(values[2], None);
        assert_eq!(values[3], Some(38));
        assert_eq!(values[4], None);
        assert_eq!(values[5], Some(40));
    } else {
        panic!("Expected IntegerArray");
    }
}

#[test]
fn test_build_sparse_array_value_enum() {
    let registry = common::create_test_registry();
    let gpio_modes_var = registry.get_variable("GPIO_MODES").unwrap();

    let indices = vec![(0, "input"), (2, "output"), (7, "bidirectional")];
    let result = traits::build_sparse_array_value(gpio_modes_var, indices).unwrap();

    if let MlxValueType::EnumArray(values) = &result.value {
        assert_eq!(values.len(), 8);
        assert_eq!(values[0], Some("input".to_string()));
        assert_eq!(values[1], None);
        assert_eq!(values[2], Some("output".to_string()));
        assert_eq!(values[3], None);
        assert_eq!(values[4], None);
        assert_eq!(values[5], None);
        assert_eq!(values[6], None);
        assert_eq!(values[7], Some("bidirectional".to_string()));
    } else {
        panic!("Expected EnumArray");
    }
}

#[test]
fn test_build_sparse_array_value_out_of_bounds() {
    let registry = common::create_test_registry();
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap(); // Size 4

    let indices = vec![(0, true), (4, false)]; // Index 4 is out of bounds
    let result = traits::build_sparse_array_value(gpio_var, indices);

    assert!(result.is_err());
    if let Err(mlxconfig_runner::MlxRunnerError::ArraySizeMismatch {
        expected, found, ..
    }) = result
    {
        assert_eq!(expected, 4);
        assert_eq!(found, 5); // Index 4 + 1
    } else {
        panic!("Expected ArraySizeMismatch error");
    }
}

#[test]
fn test_build_sparse_array_value_invalid_enum() {
    let registry = common::create_test_registry();
    let gpio_modes_var = registry.get_variable("GPIO_MODES").unwrap();

    let indices = vec![(0, "invalid_mode")];
    let result = traits::build_sparse_array_value(gpio_modes_var, indices);

    assert!(result.is_err());
}

#[test]
fn test_get_array_size_from_spec() {
    use mlxconfig_variables::MlxVariableSpec;

    // Test boolean array
    let spec = MlxVariableSpec::builder()
        .boolean_array()
        .with_size(4)
        .build();
    let size = traits::get_array_size_from_spec(&spec).unwrap();
    assert_eq!(size, 4);

    // Test integer array
    let spec = MlxVariableSpec::builder()
        .integer_array()
        .with_size(6)
        .build();
    let size = traits::get_array_size_from_spec(&spec).unwrap();
    assert_eq!(size, 6);

    // Test enum array
    let spec = MlxVariableSpec::builder()
        .enum_array()
        .with_options(vec!["a".to_string(), "b".to_string()])
        .with_size(8)
        .build();
    let size = traits::get_array_size_from_spec(&spec).unwrap();
    assert_eq!(size, 8);

    // Test binary array
    let spec = MlxVariableSpec::builder()
        .binary_array()
        .with_size(2)
        .build();
    let size = traits::get_array_size_from_spec(&spec).unwrap();
    assert_eq!(size, 2);

    // Test non-array spec should error
    let spec = MlxVariableSpec::builder().boolean().build();
    let result = traits::get_array_size_from_spec(&spec);
    assert!(result.is_err());
}

#[test]
fn test_mixed_variables_and_arrays() {
    let registry = common::create_test_registry();

    let assignments = &[
        ("SRIOV_EN", "true"),         // Regular boolean
        ("NUM_OF_VFS", "32"),         // Regular integer
        ("GPIO_ENABLED[0]", "true"),  // Array index
        ("GPIO_ENABLED[3]", "false"), // Array index
        ("POWER_MODE", "HIGH"),       // Regular enum
        ("GPIO_MODES[1]", "output"),  // Array index
    ];

    let result = assignments.to_config_values(&registry).unwrap();

    // Should have 5 config values: SRIOV_EN, NUM_OF_VFS, GPIO_ENABLED array, POWER_MODE, GPIO_MODES array
    assert_eq!(result.len(), 5);

    // Verify regular variables
    let sriov = result.iter().find(|v| v.name() == "SRIOV_EN").unwrap();
    assert_eq!(sriov.value, MlxValueType::Boolean(true));

    let vfs = result.iter().find(|v| v.name() == "NUM_OF_VFS").unwrap();
    assert_eq!(vfs.value, MlxValueType::Integer(32));

    let power = result.iter().find(|v| v.name() == "POWER_MODE").unwrap();
    assert_eq!(power.value, MlxValueType::Enum("HIGH".to_string()));

    // Verify sparse arrays
    let gpio_enabled = result.iter().find(|v| v.name() == "GPIO_ENABLED").unwrap();
    if let MlxValueType::BooleanArray(values) = &gpio_enabled.value {
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], None);
        assert_eq!(values[2], None);
        assert_eq!(values[3], Some(false));
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }

    let gpio_modes = result.iter().find(|v| v.name() == "GPIO_MODES").unwrap();
    if let MlxValueType::EnumArray(values) = &gpio_modes.value {
        assert_eq!(values[0], None);
        assert_eq!(values[1], Some("output".to_string()));
        assert!(values[2..8].iter().all(|v| v.is_none()));
    } else {
        panic!("Expected EnumArray for GPIO_MODES");
    }
}

#[test]
fn test_mlx_config_queryable_single_array_index() {
    let registry = common::create_test_registry();

    // Test querying specific array indices
    let variables = &["GPIO_ENABLED[0]", "GPIO_ENABLED[2]", "THERMAL_SENSORS[3]"];
    let result = variables.to_variable_names(&registry).unwrap();

    // Should return exactly the specified indices, not expanded arrays
    assert_eq!(result.len(), 3);
    assert!(result.contains(&"GPIO_ENABLED[0]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[2]".to_string()));
    assert!(result.contains(&"THERMAL_SENSORS[3]".to_string()));

    // Should NOT contain other indices
    assert!(!result.contains(&"GPIO_ENABLED[1]".to_string()));
    assert!(!result.contains(&"THERMAL_SENSORS[0]".to_string()));
}

#[test]
fn test_mlx_config_queryable_mixed_array_and_indices() {
    let registry = common::create_test_registry();

    // Test mixing full array names with specific indices
    let variables = &[
        "SRIOV_EN",           // Regular variable
        "GPIO_ENABLED",       // Full array (should expand)
        "THERMAL_SENSORS[1]", // Specific index
        "GPIO_MODES[7]",      // Specific index
    ];
    let result = variables.to_variable_names(&registry).unwrap();

    // Should have: SRIOV_EN + 4 GPIO_ENABLED indices + 1 THERMAL_SENSORS index + 1 GPIO_MODES index
    assert_eq!(result.len(), 7); // 1 + 4 + 1 + 1

    // Verify regular variable
    assert!(result.contains(&"SRIOV_EN".to_string()));

    // Verify full array expansion
    assert!(result.contains(&"GPIO_ENABLED[0]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[1]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[2]".to_string()));
    assert!(result.contains(&"GPIO_ENABLED[3]".to_string()));

    // Verify specific indices
    assert!(result.contains(&"THERMAL_SENSORS[1]".to_string()));
    assert!(result.contains(&"GPIO_MODES[7]".to_string()));

    // Should NOT contain other THERMAL_SENSORS or GPIO_MODES indices
    assert!(!result.contains(&"THERMAL_SENSORS[0]".to_string()));
    assert!(!result.contains(&"GPIO_MODES[0]".to_string()));
}

#[test]
fn test_mlx_config_queryable_array_index_out_of_bounds() {
    let registry = common::create_test_registry();

    // GPIO_ENABLED has size 4, so index 4 is out of bounds
    let variables = &["GPIO_ENABLED[4]"];
    let result = variables.to_variable_names(&registry);

    assert!(result.is_err());
    if let Err(mlxconfig_runner::MlxRunnerError::ArraySizeMismatch {
        variable_name,
        expected,
        found,
    }) = result
    {
        assert_eq!(variable_name, "GPIO_ENABLED");
        assert_eq!(expected, 4);
        assert_eq!(found, 5); // index 4 + 1
    } else {
        panic!("Expected ArraySizeMismatch error");
    }
}

#[test]
fn test_mlx_config_queryable_array_index_base_variable_not_found() {
    let registry = common::create_test_registry();

    // Test array index syntax with non-existent base variable
    let variables = &["NONEXISTENT_ARRAY[0]"];
    let result = variables.to_variable_names(&registry);

    assert!(result.is_err());
    if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_ARRAY");
    } else {
        panic!("Expected VariableNotFound error");
    }
}

#[test]
fn test_mlx_config_queryable_array_index_validation() {
    let registry = common::create_test_registry();

    // Test that array index validation works for different array types
    let test_cases = vec![
        ("GPIO_ENABLED[0]", true),     // BooleanArray size 4, index 0 valid
        ("GPIO_ENABLED[3]", true),     // BooleanArray size 4, index 3 valid
        ("GPIO_ENABLED[4]", false),    // BooleanArray size 4, index 4 invalid
        ("THERMAL_SENSORS[5]", true),  // IntegerArray size 6, index 5 valid
        ("THERMAL_SENSORS[6]", false), // IntegerArray size 6, index 6 invalid
        ("GPIO_MODES[7]", true),       // EnumArray size 8, index 7 valid
        ("GPIO_MODES[8]", false),      // EnumArray size 8, index 8 invalid
    ];

    for (var_name, should_succeed) in test_cases {
        let variables = &[var_name];
        let result = variables.to_variable_names(&registry);

        if should_succeed {
            assert!(result.is_ok(), "Expected {var_name} to succeed");
            let names = result.unwrap();
            assert_eq!(names.len(), 1);
            assert_eq!(names[0], var_name);
        } else {
            assert!(result.is_err(), "Expected {var_name} to fail");
        }
    }
}

#[test]
fn test_mlx_config_queryable_array_index_with_non_array_variable() {
    let registry = common::create_test_registry();

    // Test what happens when we try to use array syntax on a non-array variable
    // This should fail when trying to get array size from the spec
    let variables = &["SRIOV_EN[0]"]; // SRIOV_EN is boolean, not array
    let result = variables.to_variable_names(&registry);

    assert!(result.is_err());
    // Should get a ValueConversion error when trying to get array size from boolean spec
}

#[test]
fn test_mlx_config_queryable_preserve_vs_expand_behavior() {
    let registry = common::create_test_registry();

    // Test that behavior is consistent: specific indices are preserved, base names are expanded

    // Query just the base array name - should expand all indices
    let base_query = &["GPIO_ENABLED"];
    let base_result = base_query.to_variable_names(&registry).unwrap();
    assert_eq!(base_result.len(), 4); // Full expansion

    // Query specific indices - should preserve exact indices
    let index_query = &["GPIO_ENABLED[1]", "GPIO_ENABLED[3]"];
    let index_result = index_query.to_variable_names(&registry).unwrap();
    assert_eq!(index_result.len(), 2); // Only specified indices
    assert!(index_result.contains(&"GPIO_ENABLED[1]".to_string()));
    assert!(index_result.contains(&"GPIO_ENABLED[3]".to_string()));
    assert!(!index_result.contains(&"GPIO_ENABLED[0]".to_string()));
    assert!(!index_result.contains(&"GPIO_ENABLED[2]".to_string()));
}

#[test]
fn test_mlx_config_queryable_array_index_edge_cases() {
    let registry = common::create_test_registry();

    // Test edge cases for array index parsing and validation
    let test_cases = vec![
        ("GPIO_ENABLED[0]", true),    // First index
        ("THERMAL_SENSORS[5]", true), // Last valid index (size 6, so 0-5 valid)
        ("GPIO_MODES[0]", true),      // First index of larger array
        ("GPIO_MODES[7]", true),      // Last valid index (size 8, so 0-7 valid)
    ];

    for (var_name, should_succeed) in test_cases {
        let variables = &[var_name];
        let result = variables.to_variable_names(&registry);

        if should_succeed {
            assert!(result.is_ok(), "Expected {var_name} to succeed");
            let names = result.unwrap();
            assert_eq!(names.len(), 1);
            assert_eq!(names[0], var_name);
        } else {
            assert!(result.is_err(), "Expected {var_name} to fail");
        }
    }
}
