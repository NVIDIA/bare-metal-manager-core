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

use mlxconfig_variables::MlxVariableSpec;

#[test]
fn test_simple_variable_specs() {
    let boolean_spec = MlxVariableSpec::builder().boolean().build();
    matches!(boolean_spec, MlxVariableSpec::Boolean);

    let integer_spec = MlxVariableSpec::builder().integer().build();
    matches!(integer_spec, MlxVariableSpec::Integer);

    let string_spec = MlxVariableSpec::builder().string().build();
    matches!(string_spec, MlxVariableSpec::String);

    let binary_spec = MlxVariableSpec::builder().binary().build();
    matches!(binary_spec, MlxVariableSpec::Binary);

    let bytes_spec = MlxVariableSpec::builder().bytes().build();
    matches!(bytes_spec, MlxVariableSpec::Bytes);

    let array_spec = MlxVariableSpec::builder().array().build();
    matches!(array_spec, MlxVariableSpec::Array);

    let opaque_spec = MlxVariableSpec::builder().opaque().build();
    matches!(opaque_spec, MlxVariableSpec::Opaque);
}

#[test]
fn test_enum_variable_spec() {
    let enum_spec = MlxVariableSpec::builder()
        .enum_type()
        .with_options(vec![
            "low".to_string(),
            "medium".to_string(),
            "high".to_string(),
        ])
        .build();

    match enum_spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, vec!["low", "medium", "high"]);
        }
        _ => panic!("Expected Enum variant"),
    }
}

#[test]
fn test_enum_variable_spec_empty_options() {
    let enum_spec = MlxVariableSpec::builder().enum_type().build();

    match enum_spec {
        MlxVariableSpec::Enum { options } => {
            assert!(options.is_empty());
        }
        _ => panic!("Expected Enum variant"),
    }
}

#[test]
fn test_preset_variable_spec() {
    let preset_spec = MlxVariableSpec::builder()
        .preset()
        .with_max_preset(10)
        .build();

    match preset_spec {
        MlxVariableSpec::Preset { max_preset } => {
            assert_eq!(max_preset, 10);
        }
        _ => panic!("Expected Preset variant"),
    }
}

#[test]
fn test_preset_variable_spec_default() {
    let preset_spec = MlxVariableSpec::builder().preset().build();

    match preset_spec {
        MlxVariableSpec::Preset { max_preset } => {
            assert_eq!(max_preset, 0);
        }
        _ => panic!("Expected Preset variant"),
    }
}

#[test]
fn test_boolean_array_variable_spec() {
    let bool_array_spec = MlxVariableSpec::builder()
        .boolean_array()
        .with_size(8)
        .build();

    match bool_array_spec {
        MlxVariableSpec::BooleanArray { size } => {
            assert_eq!(size, 8);
        }
        _ => panic!("Expected BooleanArray variant"),
    }
}

#[test]
fn test_boolean_array_variable_spec_default() {
    let bool_array_spec = MlxVariableSpec::builder().boolean_array().build();

    match bool_array_spec {
        MlxVariableSpec::BooleanArray { size } => {
            assert_eq!(size, 1);
        }
        _ => panic!("Expected BooleanArray variant"),
    }
}

#[test]
fn test_integer_array_variable_spec() {
    let int_array_spec = MlxVariableSpec::builder()
        .integer_array()
        .with_size(6)
        .build();

    match int_array_spec {
        MlxVariableSpec::IntegerArray { size } => {
            assert_eq!(size, 6);
        }
        _ => panic!("Expected IntegerArray variant"),
    }
}

#[test]
fn test_integer_array_variable_spec_default() {
    let int_array_spec = MlxVariableSpec::builder().integer_array().build();

    match int_array_spec {
        MlxVariableSpec::IntegerArray { size } => {
            assert_eq!(size, 1);
        }
        _ => panic!("Expected IntegerArray variant"),
    }
}

#[test]
fn test_binary_array_variable_spec() {
    let binary_array_spec = MlxVariableSpec::builder()
        .binary_array()
        .with_size(4)
        .build();

    match binary_array_spec {
        MlxVariableSpec::BinaryArray { size } => {
            assert_eq!(size, 4);
        }
        _ => panic!("Expected BinaryArray variant"),
    }
}

#[test]
fn test_binary_array_variable_spec_default() {
    let binary_array_spec = MlxVariableSpec::builder().binary_array().build();

    match binary_array_spec {
        MlxVariableSpec::BinaryArray { size } => {
            assert_eq!(size, 1);
        }
        _ => panic!("Expected BinaryArray variant"),
    }
}

#[test]
fn test_enum_array_variable_spec() {
    let enum_array_spec = MlxVariableSpec::builder()
        .enum_array()
        .with_options(vec![
            "input".to_string(),
            "output".to_string(),
            "bidirectional".to_string(),
        ])
        .with_size(8)
        .build();

    match enum_array_spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert_eq!(options, vec!["input", "output", "bidirectional"]);
            assert_eq!(size, 8);
        }
        _ => panic!("Expected EnumArray variant"),
    }
}

#[test]
fn test_enum_array_variable_spec_defaults() {
    let enum_array_spec = MlxVariableSpec::builder().enum_array().build();

    match enum_array_spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert!(options.is_empty());
            assert_eq!(size, 1);
        }
        _ => panic!("Expected EnumArray variant"),
    }
}

#[test]
fn test_serde_serialization_simple_types() {
    let specs = vec![
        MlxVariableSpec::Boolean,
        MlxVariableSpec::Integer,
        MlxVariableSpec::String,
        MlxVariableSpec::Binary,
        MlxVariableSpec::Bytes,
        MlxVariableSpec::Array,
        MlxVariableSpec::Opaque,
    ];

    for spec in specs {
        let json = serde_json::to_string(&spec).expect("Serialization failed");
        let deserialized: MlxVariableSpec =
            serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(format!("{spec:?}"), format!("{deserialized:?}"));
    }
}

#[test]
fn test_serde_serialization_complex_types() {
    let enum_spec = MlxVariableSpec::Enum {
        options: vec!["low".to_string(), "high".to_string()],
    };
    let json = serde_json::to_string(&enum_spec).expect("Serialization failed");
    let deserialized: MlxVariableSpec =
        serde_json::from_str(&json).expect("Deserialization failed");
    match deserialized {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, vec!["low", "high"]);
        }
        _ => panic!("Expected Enum variant"),
    }

    let preset_spec = MlxVariableSpec::Preset { max_preset: 5 };
    let json = serde_json::to_string(&preset_spec).expect("Serialization failed");
    let deserialized: MlxVariableSpec =
        serde_json::from_str(&json).expect("Deserialization failed");
    match deserialized {
        MlxVariableSpec::Preset { max_preset } => {
            assert_eq!(max_preset, 5);
        }
        _ => panic!("Expected Preset variant"),
    }
}

#[test]
fn test_yaml_deserialization_from_file_examples() {
    // Test YAML format that matches the registry files
    let yaml_enum = r#"
type: "enum"
config:
  options: ["low", "medium", "high", "turbo"]
"#;

    let spec: MlxVariableSpec =
        serde_yaml::from_str(yaml_enum).expect("YAML deserialization failed");
    match spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, vec!["low", "medium", "high", "turbo"]);
        }
        _ => panic!("Expected Enum variant"),
    }

    let yaml_enum_array = r#"
type: "enum_array"
config:
  options: ["input", "output", "bidirectional"]
  size: 8
"#;

    let spec: MlxVariableSpec =
        serde_yaml::from_str(yaml_enum_array).expect("YAML deserialization failed");
    match spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert_eq!(options, vec!["input", "output", "bidirectional"]);
            assert_eq!(size, 8);
        }
        _ => panic!("Expected EnumArray variant"),
    }

    let yaml_simple = r#"
type: "boolean"
"#;

    let spec: MlxVariableSpec =
        serde_yaml::from_str(yaml_simple).expect("YAML deserialization failed");
    matches!(spec, MlxVariableSpec::Boolean);
}
