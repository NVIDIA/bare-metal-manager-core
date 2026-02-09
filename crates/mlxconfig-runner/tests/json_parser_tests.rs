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

// tests/json_parser_tests.rs
// Tests for JsonResponseParser functionality

use std::fs;

use mlxconfig_runner::ExecOptions;
use mlxconfig_runner::json_parser::JsonResponseParser;
use mlxconfig_variables::MlxValueType;
use serde_json::json;

mod common;

#[test]
fn test_parse_basic_json_response() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = common::create_sample_json_response("01:00.0");

    // Write JSON to temp file
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();

    // Verify device info
    assert_eq!(
        result.device_info.device_type,
        Some("BlueField3".to_string())
    );
    assert_eq!(
        result.device_info.part_number,
        Some("900-9D3D4-00EN-HA0_Ax".to_string())
    );

    // Verify variables were parsed
    assert_eq!(result.variables.len(), 5); // SRIOV_EN, NUM_OF_VFS, POWER_MODE, DEVICE_NAME, PERFORMANCE_PRESET

    // Check SRIOV_EN boolean parsing
    let sriov_var = result
        .variables
        .iter()
        .find(|v| v.name() == "SRIOV_EN")
        .unwrap();

    assert_eq!(sriov_var.current_value.value, MlxValueType::Boolean(true));
    assert_eq!(sriov_var.default_value.value, MlxValueType::Boolean(false));
    assert_eq!(sriov_var.next_value.value, MlxValueType::Boolean(true));
    assert!(sriov_var.modified);
    assert!(!sriov_var.read_only);
}

#[test]
fn test_parse_array_variables() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = common::create_array_json_response("01:00.0");

    // Write JSON to temp file
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();

    // Find GPIO_ENABLED boolean array
    let gpio_enabled = result
        .variables
        .iter()
        .find(|v| v.name() == "GPIO_ENABLED")
        .unwrap();

    if let MlxValueType::BooleanArray(values) = &gpio_enabled.current_value.value {
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Some(true));
        assert_eq!(values[1], Some(false));
        assert_eq!(values[2], Some(true));
        assert_eq!(values[3], Some(false));
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }

    // Find THERMAL_SENSORS integer array
    let thermal_sensors = result
        .variables
        .iter()
        .find(|v| v.name() == "THERMAL_SENSORS")
        .unwrap();

    if let MlxValueType::IntegerArray(values) = &thermal_sensors.current_value.value {
        assert_eq!(values.len(), 6);
        assert_eq!(values[0], Some(45));
        assert_eq!(values[1], Some(38));
        assert_eq!(values[2], Some(42));
        assert_eq!(values[3], Some(41));
        assert_eq!(values[4], Some(39));
        assert_eq!(values[5], Some(40));
    } else {
        panic!("Expected IntegerArray for THERMAL_SENSORS");
    }

    // Find GPIO_MODES enum array
    let gpio_modes = result
        .variables
        .iter()
        .find(|v| v.name() == "GPIO_MODES")
        .unwrap();

    if let MlxValueType::EnumArray(values) = &gpio_modes.current_value.value {
        assert_eq!(values.len(), 8);
        assert_eq!(values[0], Some("input".to_string()));
        assert_eq!(values[1], Some("output".to_string()));
        assert_eq!(values[2], Some("bidirectional".to_string()));
        assert_eq!(values[3], Some("input".to_string()));
        assert_eq!(values[4], Some("output".to_string()));
        assert_eq!(values[5], Some("input".to_string()));
        assert_eq!(values[6], Some("input".to_string()));
        assert_eq!(values[7], Some("input".to_string()));
    } else {
        panic!("Expected EnumArray for GPIO_MODES");
    }
}

#[test]
fn test_device_mismatch_error() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = common::create_sample_json_response("01:00.0");

    // Write JSON to temp file
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    // Try to parse with different expected device
    let result = parser.parse_json_response(temp_file.path(), "02:00.0");

    assert!(result.is_err());
    if let Err(mlxconfig_runner::MlxRunnerError::DeviceMismatch { expected, actual }) = result {
        assert_eq!(expected, "02:00.0");
        assert_eq!(actual, "01:00.0");
    } else {
        panic!("Expected DeviceMismatch error");
    }
}

#[test]
fn test_malformed_json() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let malformed_json = r#"{"Device #1": {"invalid": "structure"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), malformed_json).unwrap();

    let result = parser.parse_json_response(temp_file.path(), "01:00.0");

    assert!(result.is_err());
}

#[test]
fn test_missing_file() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let nonexistent_path = std::path::Path::new("/nonexistent/file.json");
    let result = parser.parse_json_response(nonexistent_path, "01:00.0");

    assert!(result.is_err());
}

#[test]
fn test_boolean_parsing_variations() {
    let registry = common::create_minimal_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    // Test different boolean formats that mlxconfig might return
    let test_cases = vec![
        ("True(1)", true),
        ("False(0)", false),
        ("TRUE", true),
        ("FALSE", false),
    ];

    for (input_value, expected_bool) in test_cases {
        let json_data = json!({
            "Device #1": {
                "description": "Test Device",
                "device": "01:00.0",
                "device_type": "Test",
                "name": "Test",
                "tlv_configuration": {
                    "TEST_BOOL": {
                        "current_value": input_value,
                        "default_value": "False(0)",
                        "modified": false,
                        "next_value": input_value,
                        "read_only": false
                    }
                }
            }
        });

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let json_string = serde_json::to_string_pretty(&json_data).unwrap();
        fs::write(temp_file.path(), json_string).unwrap();

        let result = parser
            .parse_json_response(temp_file.path(), "01:00.0")
            .unwrap();
        let test_var = result
            .variables
            .iter()
            .find(|v| v.name() == "TEST_BOOL")
            .unwrap();

        assert_eq!(
            test_var.current_value.value,
            MlxValueType::Boolean(expected_bool)
        );
    }
}

#[test]
fn test_enum_parsing_with_parentheses() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "POWER_MODE": {
                    "current_value": "HIGH(2)",
                    "default_value": "LOW(0)",
                    "modified": true,
                    "next_value": "MEDIUM(1)",
                    "read_only": false
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();
    let power_var = result
        .variables
        .iter()
        .find(|v| v.name() == "POWER_MODE")
        .unwrap();

    // Should strip parentheses and numbers
    assert_eq!(
        power_var.current_value.value,
        MlxValueType::Enum("HIGH".to_string())
    );
    assert_eq!(
        power_var.default_value.value,
        MlxValueType::Enum("LOW".to_string())
    );
    assert_eq!(
        power_var.next_value.value,
        MlxValueType::Enum("MEDIUM".to_string())
    );
}

#[test]
fn test_integer_parsing() {
    let registry = common::create_minimal_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "TEST_INT": {
                    "current_value": 42,
                    "default_value": 0,
                    "modified": true,
                    "next_value": 100,
                    "read_only": false
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();
    let int_var = result
        .variables
        .iter()
        .find(|v| v.name() == "TEST_INT")
        .unwrap();

    assert_eq!(int_var.current_value.value, MlxValueType::Integer(42));
    assert_eq!(int_var.default_value.value, MlxValueType::Integer(0));
    assert_eq!(int_var.next_value.value, MlxValueType::Integer(100));
    assert!(int_var.modified);
}

#[test]
fn test_sparse_array_with_missing_indices() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    // JSON with only some array indices present (simulating sparse array from device)
    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "GPIO_ENABLED[0]": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": true,
                    "next_value": "True(1)",
                    "read_only": false
                },
                "GPIO_ENABLED[2]": {
                    "current_value": "False(0)",
                    "default_value": "False(0)",
                    "modified": false,
                    "next_value": "False(0)",
                    "read_only": false
                }
                // Note: GPIO_ENABLED[1] and GPIO_ENABLED[3] are missing
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();
    let gpio_var = result
        .variables
        .iter()
        .find(|v| v.name() == "GPIO_ENABLED")
        .unwrap();

    if let MlxValueType::BooleanArray(values) = &gpio_var.current_value.value {
        assert_eq!(values.len(), 4); // Array size should match registry spec
        assert_eq!(values[0], Some(true)); // Present in JSON
        assert_eq!(values[1], None); // Missing from JSON
        assert_eq!(values[2], Some(false)); // Present in JSON
        assert_eq!(values[3], None); // Missing from JSON
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }
}

#[test]
fn test_unknown_variable_in_json() {
    let registry = common::create_minimal_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "TEST_BOOL": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": false,
                    "next_value": "True(1)",
                    "read_only": false
                },
                "UNKNOWN_VARIABLE": {
                    "current_value": "some_value",
                    "default_value": "default",
                    "modified": false,
                    "next_value": "some_value",
                    "read_only": false
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();

    // Should only parse known variables from registry
    assert_eq!(result.variables.len(), 1);
    assert_eq!(result.variables[0].name(), "TEST_BOOL");
}

#[test]
fn test_log_json_output_option() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_log_json_output(true);
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = common::create_sample_json_response("01:00.0");

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    // Should not fail even with logging enabled
    let result = parser.parse_json_response(temp_file.path(), "01:00.0");
    assert!(result.is_ok());
}

#[test]
fn test_array_size_validation() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    // Create JSON with array that matches registry size exactly
    // GPIO_ENABLED should have size 4
    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "GPIO_ENABLED[0]": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": true,
                    "next_value": "True(1)",
                    "read_only": false
                },
                "GPIO_ENABLED[1]": {
                    "current_value": "False(0)",
                    "default_value": "False(0)",
                    "modified": false,
                    "next_value": "False(0)",
                    "read_only": false
                },
                "GPIO_ENABLED[2]": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": true,
                    "next_value": "True(1)",
                    "read_only": false
                },
                "GPIO_ENABLED[3]": {
                    "current_value": "False(0)",
                    "default_value": "False(0)",
                    "modified": false,
                    "next_value": "False(0)",
                    "read_only": false
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();
    let gpio_var = result
        .variables
        .iter()
        .find(|v| v.name() == "GPIO_ENABLED")
        .unwrap();

    // Should parse correctly with expected size
    if let MlxValueType::BooleanArray(values) = &gpio_var.current_value.value {
        assert_eq!(values.len(), 4); // Should match registry spec
    } else {
        panic!("Expected BooleanArray for GPIO_ENABLED");
    }
}

#[test]
fn test_read_only_flag_parsing() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "DEVICE_NAME": {
                    "current_value": "test-device",
                    "default_value": "test-device",
                    "modified": false,
                    "next_value": "test-device",
                    "read_only": true
                },
                "SRIOV_EN": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": true,
                    "next_value": "True(1)",
                    "read_only": false
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();

    let device_name_var = result
        .variables
        .iter()
        .find(|v| v.name() == "DEVICE_NAME")
        .unwrap();
    let sriov_var = result
        .variables
        .iter()
        .find(|v| v.name() == "SRIOV_EN")
        .unwrap();

    assert!(device_name_var.read_only);
    assert!(!sriov_var.read_only);
}

#[test]
fn test_modified_flag_parsing() {
    let registry = common::create_test_registry();
    let options = ExecOptions::default();
    let parser = JsonResponseParser::new(&registry, &options);

    let json_data = json!({
        "Device #1": {
            "description": "Test Device",
            "device": "01:00.0",
            "device_type": "Test",
            "name": "Test",
            "tlv_configuration": {
                "SRIOV_EN": {
                    "current_value": "True(1)",
                    "default_value": "False(0)",
                    "modified": true,
                    "next_value": "True(1)",
                    "read_only": false
                },
                "DEVICE_NAME": {
                    "current_value": "test-device",
                    "default_value": "test-device",
                    "modified": false,
                    "next_value": "test-device",
                    "read_only": true
                }
            }
        }
    });

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    let result = parser
        .parse_json_response(temp_file.path(), "01:00.0")
        .unwrap();

    let sriov_var = result
        .variables
        .iter()
        .find(|v| v.name() == "SRIOV_EN")
        .unwrap();
    let device_name_var = result
        .variables
        .iter()
        .find(|v| v.name() == "DEVICE_NAME")
        .unwrap();

    assert!(sriov_var.modified);
    assert!(!device_name_var.modified);
}
