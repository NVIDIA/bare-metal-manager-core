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

use mac_address::MacAddress;
use mlxconfig_device::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};
use mlxconfig_device::info::MlxDeviceInfo;
use mlxconfig_variables::{MlxConfigVariable, MlxVariableRegistry, MlxVariableSpec};

// create_test_variables creates a set of test variables for registry testing.
fn create_test_variables() -> Vec<MlxConfigVariable> {
    vec![
        MlxConfigVariable::builder()
            .name("BOOL_VAR".to_string())
            .description("A boolean variable".to_string())
            .read_only(false)
            .spec(MlxVariableSpec::Boolean)
            .build(),
        MlxConfigVariable::builder()
            .name("INT_VAR".to_string())
            .description("An integer variable".to_string())
            .read_only(false)
            .spec(MlxVariableSpec::Integer)
            .build(),
        MlxConfigVariable::builder()
            .name("ENUM_VAR".to_string())
            .description("An enum variable".to_string())
            .read_only(false)
            .spec(MlxVariableSpec::Enum {
                options: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
            })
            .build(),
        MlxConfigVariable::builder()
            .name("ARRAY_VAR".to_string())
            .description("An integer array variable".to_string())
            .read_only(false)
            .spec(MlxVariableSpec::IntegerArray { size: 4 })
            .build(),
    ]
}

// create_test_device creates a test device for filter testing.
fn create_test_device(device_type: &str, part_number: &str, fw_version: &str) -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: "01:00.0".to_string(),
        device_type: device_type.to_string(),
        psid: Some("MT_0000000001".to_string()),
        device_description: Some("Test device".to_string()),
        part_number: Some(part_number.to_string()),
        fw_version_current: Some(fw_version.to_string()),
        pxe_version_current: Some("3.6.0102".to_string()),
        uefi_version_current: Some("14.25.1020".to_string()),
        uefi_version_virtio_blk_current: Some("1.0.00".to_string()),
        uefi_version_virtio_net_current: Some("1.0.00".to_string()),
        base_mac: Some(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        status: None,
    }
}

#[test]
fn test_registry_creation_basic() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("test_registry").variables(variables);

    assert_eq!(registry.name, "test_registry");
    assert_eq!(registry.variables.len(), 4);
    assert!(registry.filters.is_none());
    assert!(!registry.has_filters());
}

#[test]
fn test_registry_builder_pattern() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("builder_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ));

    assert_eq!(registry.name, "builder_test");
    assert_eq!(registry.variables.len(), 4);
    assert!(registry.has_filters());
}

#[test]
fn test_registry_get_variable() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("lookup_test").variables(variables);

    // Test finding existing variables
    let bool_var = registry.get_variable("BOOL_VAR");
    assert!(bool_var.is_some());
    assert_eq!(bool_var.unwrap().name, "BOOL_VAR");
    assert_eq!(bool_var.unwrap().description, "A boolean variable");
    assert!(!bool_var.unwrap().read_only);

    let enum_var = registry.get_variable("ENUM_VAR");
    assert!(enum_var.is_some());
    match &enum_var.unwrap().spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, &vec!["low", "medium", "high"]);
        }
        _ => panic!("Expected Enum spec"),
    }

    // Test non-existent variable
    let missing_var = registry.get_variable("NON_EXISTENT");
    assert!(missing_var.is_none());
}

#[test]
fn test_registry_variable_names() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("names_test").variables(variables);

    let names = registry.variable_names();
    assert_eq!(names.len(), 4);
    assert!(names.contains(&"BOOL_VAR"));
    assert!(names.contains(&"INT_VAR"));
    assert!(names.contains(&"ENUM_VAR"));
    assert!(names.contains(&"ARRAY_VAR"));
}

#[test]
fn test_registry_with_single_filter() {
    let variables = create_test_variables();
    let filter = DeviceFilter::new(
        DeviceField::DeviceType,
        vec!["BlueField3".to_string()],
        MatchMode::Exact,
    );

    let registry = MlxVariableRegistry::new("single_filter_test")
        .variables(variables)
        .with_filter(filter);

    assert!(registry.has_filters());
    assert_eq!(registry.filters.as_ref().unwrap().filters.len(), 1);

    let filter_summary = registry.filter_summary();
    assert!(filter_summary.contains("device_type"));
    assert!(filter_summary.contains("BlueField3"));
    assert!(filter_summary.contains("exact"));
}

#[test]
fn test_registry_with_multiple_filters() {
    let variables = create_test_variables();

    let registry = MlxVariableRegistry::new("multi_filter_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string(), "ConnectX-6".to_string()],
            MatchMode::Exact,
        ))
        .with_filter(DeviceFilter::new(
            DeviceField::PartNumber,
            vec!["MCX.*".to_string()],
            MatchMode::Regex,
        ));

    assert!(registry.has_filters());
    assert_eq!(registry.filters.as_ref().unwrap().filters.len(), 2);

    let filter_summary = registry.filter_summary();
    assert!(filter_summary.contains("device_type"));
    assert!(filter_summary.contains("part_number"));
}

#[test]
fn test_registry_with_filter_set() {
    let variables = create_test_variables();

    let mut filter_set = DeviceFilterSet::default();
    filter_set.add_filter(DeviceFilter::new(
        DeviceField::DeviceType,
        vec!["BlueField3".to_string()],
        MatchMode::Exact,
    ));
    filter_set.add_filter(DeviceFilter::new(
        DeviceField::FirmwareVersion,
        vec!["28.*.1010".to_string()],
        MatchMode::Regex,
    ));

    let registry = MlxVariableRegistry::new("filter_set_test")
        .variables(variables)
        .with_filters(filter_set);

    assert!(registry.has_filters());
    assert_eq!(registry.filters.as_ref().unwrap().filters.len(), 2);
}

#[test]
fn test_registry_device_matching_no_filters() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("no_filter_test").variables(variables);

    let device = create_test_device("BlueField3", "MCX623106AS-CDAT", "28.38.1010");

    // Registry with no filters should match any device
    assert!(registry.matches_device(&device));
}

#[test]
fn test_registry_device_matching_with_filters() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("device_match_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ))
        .with_filter(DeviceFilter::new(
            DeviceField::PartNumber,
            vec!["MCX.*".to_string()],
            MatchMode::Regex,
        ));

    // Device that matches both filters
    let matching_device = create_test_device("BlueField3", "MCX623106AS-CDAT", "28.38.1010");
    assert!(registry.matches_device(&matching_device));

    // Device that matches only first filter
    let partial_match_device = create_test_device("BlueField3", "MT40354", "28.38.1010");
    assert!(!registry.matches_device(&partial_match_device));

    // Device that matches no filters
    let non_matching_device = create_test_device("ConnectX-6", "MT40354", "28.38.1010");
    assert!(!registry.matches_device(&non_matching_device));
}

#[test]
fn test_registry_filter_summary_empty() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("empty_filter_test").variables(variables);

    assert_eq!(registry.filter_summary(), "No filters");
}

#[test]
fn test_registry_filter_summary_with_filters() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("summary_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ));

    let summary = registry.filter_summary();
    assert!(summary.contains("device_type"));
    assert!(summary.contains("BlueField3"));
    assert!(summary.contains("exact"));
}

#[test]
fn test_registry_serde_serialization_no_filters() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("serde_test").variables(variables);

    // Test JSON serialization
    let json = serde_json::to_string(&registry).expect("JSON serialization failed");
    let deserialized: MlxVariableRegistry =
        serde_json::from_str(&json).expect("JSON deserialization failed");

    assert_eq!(registry.name, deserialized.name);
    assert_eq!(registry.variables.len(), deserialized.variables.len());
    assert!(!deserialized.has_filters());

    // Test YAML serialization
    let yaml = serde_yaml::to_string(&registry).expect("YAML serialization failed");
    let yaml_deserialized: MlxVariableRegistry =
        serde_yaml::from_str(&yaml).expect("YAML deserialization failed");

    assert_eq!(registry.name, yaml_deserialized.name);
    assert_eq!(registry.variables.len(), yaml_deserialized.variables.len());
    assert!(!yaml_deserialized.has_filters());
}

#[test]
fn test_registry_serde_serialization_with_filters() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("serde_filter_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ));

    // Test JSON serialization with filters
    let json = serde_json::to_string(&registry).expect("JSON serialization failed");
    let deserialized: MlxVariableRegistry =
        serde_json::from_str(&json).expect("JSON deserialization failed");

    assert_eq!(registry.name, deserialized.name);
    assert_eq!(registry.variables.len(), deserialized.variables.len());
    assert!(deserialized.has_filters());
    assert_eq!(deserialized.filters.as_ref().unwrap().filters.len(), 1);

    // Test YAML serialization with filters
    let yaml = serde_yaml::to_string(&registry).expect("YAML serialization failed");
    let yaml_deserialized: MlxVariableRegistry =
        serde_yaml::from_str(&yaml).expect("YAML deserialization failed");

    assert_eq!(registry.name, yaml_deserialized.name);
    assert_eq!(registry.variables.len(), yaml_deserialized.variables.len());
    assert!(yaml_deserialized.has_filters());
    assert_eq!(yaml_deserialized.filters.as_ref().unwrap().filters.len(), 1);
}

#[test]
fn test_registry_yaml_format_matches_expected() {
    // Test that we can deserialize the expected YAML format
    let yaml = r#"
name: "test_registry"
filters:
  - field: device_type
    values: ["BlueField3", "ConnectX-6"]
    match_mode: exact
  - field: part_number
    values: ["MCX.*"]
    match_mode: regex
variables:
  - name: "TEST_VAR"
    description: "Test variable"
    read_only: false
    spec:
      type: "boolean"
"#;

    let registry: MlxVariableRegistry =
        serde_yaml::from_str(yaml).expect("Should deserialize expected YAML format");

    assert_eq!(registry.name, "test_registry");
    assert!(registry.has_filters());
    assert_eq!(registry.filters.as_ref().unwrap().filters.len(), 2);
    assert_eq!(registry.variables.len(), 1);
    assert_eq!(registry.variables[0].name, "TEST_VAR");
}

#[test]
fn test_registry_clone() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("clone_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ));

    let cloned = registry.clone();

    assert_eq!(registry.name, cloned.name);
    assert_eq!(registry.variables.len(), cloned.variables.len());
    assert_eq!(registry.has_filters(), cloned.has_filters());
    assert_eq!(
        registry.filters.as_ref().unwrap().filters.len(),
        cloned.filters.as_ref().unwrap().filters.len()
    );
}

#[test]
fn test_registry_debug_formatting() {
    let variables = create_test_variables();
    let registry = MlxVariableRegistry::new("debug_test")
        .variables(variables)
        .with_filter(DeviceFilter::new(
            DeviceField::DeviceType,
            vec!["BlueField3".to_string()],
            MatchMode::Exact,
        ));

    let debug_str = format!("{registry:?}");

    // Should contain all important fields
    assert!(debug_str.contains("debug_test"));
    assert!(debug_str.contains("variables"));
    assert!(debug_str.contains("filters"));
    assert!(debug_str.contains("BlueField3"));
}

#[test]
fn test_registry_empty_variables() {
    let registry = MlxVariableRegistry::new("empty_vars_test").variables(vec![]);

    assert_eq!(registry.variables.len(), 0);
    assert!(registry.variable_names().is_empty());
    assert!(registry.get_variable("ANY_VAR").is_none());
}

#[test]
fn test_registry_add_variable_builder() {
    let variable = MlxConfigVariable::builder()
        .name("SINGLE_VAR".to_string())
        .description("Single variable test".to_string())
        .read_only(false)
        .spec(MlxVariableSpec::Boolean)
        .build();

    let registry = MlxVariableRegistry::new("add_var_test").add_variable(variable);

    assert_eq!(registry.variables.len(), 1);
    assert_eq!(registry.variables[0].name, "SINGLE_VAR");

    let found_var = registry.get_variable("SINGLE_VAR");
    assert!(found_var.is_some());
    assert_eq!(found_var.unwrap().description, "Single variable test");
}

#[test]
fn test_registry_multiple_add_variable_calls() {
    let var1 = MlxConfigVariable::builder()
        .name("VAR1".to_string())
        .description("First variable".to_string())
        .read_only(false)
        .spec(MlxVariableSpec::Boolean)
        .build();

    let var2 = MlxConfigVariable::builder()
        .name("VAR2".to_string())
        .description("Second variable".to_string())
        .read_only(true)
        .spec(MlxVariableSpec::Integer)
        .build();

    let registry = MlxVariableRegistry::new("multi_add_test")
        .add_variable(var1)
        .add_variable(var2);

    assert_eq!(registry.variables.len(), 2);

    let var1_found = registry.get_variable("VAR1");
    assert!(var1_found.is_some());
    assert!(!var1_found.unwrap().read_only);

    let var2_found = registry.get_variable("VAR2");
    assert!(var2_found.is_some());
    assert!(var2_found.unwrap().read_only);
}
