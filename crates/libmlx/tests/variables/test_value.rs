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

use libmlx::variables::spec::MlxVariableSpec;
use libmlx::variables::value::{MlxValueError, MlxValueType};
use libmlx::variables::variable::MlxConfigVariable;

// create_test_variable creates a test variable with a given spec
// to use for testing. This is leveraged for basically each test.
fn create_test_variable(name: &str, spec: MlxVariableSpec) -> MlxConfigVariable {
    MlxConfigVariable {
        name: name.to_string(),
        description: format!("Test variable: {name}"),
        read_only: false,
        spec,
    }
}

// test_boolean_value_creation creates a new variable called "test_bool"
// with a boolean spec, and then makes sure we can call `with`
// on it with a boolean, ensuring the IntoMlxValue trait is working
// as expected for booleans (among other things).
#[test]
fn test_boolean_value_creation() {
    let var = create_test_variable("test_bool", MlxVariableSpec::Boolean);
    let value = var.with(true).unwrap();

    assert_eq!(value.name(), "test_bool");
    assert_eq!(value.value, MlxValueType::Boolean(true));
    assert!(!value.is_read_only());
}

// test_integer_value_creation creates a new variable called "test_int"
// with an integer spec, and then makes sure we can call `with`
// on it with an integer, ensuring the IntoMlxValue trait is working
// as expected for integers (among other things).
#[test]
fn test_integer_value_creation() {
    let var = create_test_variable("test_int", MlxVariableSpec::Integer);

    // Works with different integer types.
    let value1 = var.with(42i64).unwrap();
    let value2 = var.with(42i32).unwrap();

    assert_eq!(value1.value, MlxValueType::Integer(42));
    assert_eq!(value2.value, MlxValueType::Integer(42));
}

// test_string_value_creation creates a new variable called "test_string"
// with a string spec, and then makes sure we can call `with`
// on it with a string, ensuring the IntoMlxValue trait is working
// as expected for strings (among other things, that rhymes).
#[test]
fn test_string_value_creation() {
    let var = create_test_variable("test_string", MlxVariableSpec::String);

    // Works with &str, String, etc.
    let value1 = var.with("hello").unwrap();
    let value2 = var.with("world".to_string()).unwrap();

    assert_eq!(value1.value, MlxValueType::String("hello".to_string()));
    assert_eq!(value2.value, MlxValueType::String("world".to_string()));
}

// test_enum_value_validation creates a new variable called "test_enum"
// with an enum spec, and then makes sure we can call `with`
// on it with an enum, ensuring the IntoMlxValue trait is working
// as expected for enums (among other things).
#[test]
fn test_enum_value_validation() {
    let var = create_test_variable(
        "test_enum",
        MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        },
    );

    // Valid enum value - underlying logic it's an enum and validates.
    let valid_value = var.with("medium").unwrap();
    assert_eq!(valid_value.value, MlxValueType::Enum("medium".to_string()));

    // Invalid enum value - still gets validated.
    let invalid_result = var.with("invalid");
    assert!(invalid_result.is_err());
    match invalid_result.unwrap_err() {
        MlxValueError::InvalidEnumOption { value, allowed } => {
            assert_eq!(value, "invalid");
            assert_eq!(allowed, vec!["low", "medium", "high"]);
        }
        _ => panic!("Expected InvalidEnumOption error"),
    }
}

// test_preset_value creates a new variable called "test_preset"
// with a preset spec, and then makes sure we can call `with`
// on it with a preset, ensuring the IntoMlxValue trait is working
// as expected for presets (among other things).
#[test]
fn test_preset_value() {
    let var = create_test_variable("test_preset", MlxVariableSpec::Preset { max_preset: 5 });

    // u8 gets automatically converted to preset with validation.
    let valid_value = var.with(3u8).unwrap();
    assert_eq!(valid_value.value, MlxValueType::Preset(3));

    // Out of range preset.
    let invalid_result = var.with(10u8);
    assert!(invalid_result.is_err());
}

// test_boolean_array_creation creates a new variable called "test_bool_array"
// with a boolean array spec, and then makes sure we can call `with`
// on it with a boolean array, ensuring the IntoMlxValue trait is working
// as expected for boolean arrays (among other things).
#[test]
fn test_boolean_array_creation() {
    let var = create_test_variable("test_bool_array", MlxVariableSpec::BooleanArray { size: 4 });

    // Vec<bool> gets automatically validated for size and converted to sparse format.
    let valid_value = var.with(vec![true, false, true, false]).unwrap();
    assert_eq!(
        valid_value.value,
        MlxValueType::BooleanArray(vec![Some(true), Some(false), Some(true), Some(false)])
    );

    // Wrong size gets caught.
    let invalid_result = var.with(vec![true, false]);
    assert!(invalid_result.is_err());
}

// test_sparse_boolean_array_creation tests creating sparse boolean arrays
// where some indices are unset (None).
#[test]
fn test_sparse_boolean_array_creation() {
    let var = create_test_variable(
        "test_sparse_bool_array",
        MlxVariableSpec::BooleanArray { size: 4 },
    );

    // Vec<Option<bool>> for sparse arrays
    let sparse_value = var.with(vec![Some(true), None, Some(false), None]).unwrap();
    assert_eq!(
        sparse_value.value,
        MlxValueType::BooleanArray(vec![Some(true), None, Some(false), None])
    );

    // Display should show "-" for None values
    let display = sparse_value.to_display_string();
    assert_eq!(display, "[true, -, false, -]");

    // Wrong size gets caught
    let invalid_result = var.with(vec![Some(true), None]);
    assert!(invalid_result.is_err());
}

// test_enum_array_creation creates a new variable called "test_enum_array"
// with an enum array spec, and then makes sure we can call `with`
// on it with an enum array, ensuring the IntoMlxValue trait is working
// as expected for enum arrays (among other things).
#[test]
fn test_enum_array_creation() {
    let var = create_test_variable(
        "test_enum_array",
        MlxVariableSpec::EnumArray {
            options: vec!["input".to_string(), "output".to_string()],
            size: 3,
        },
    );

    let valid_value = var.with(vec!["input", "output", "input"]).unwrap();
    assert_eq!(
        valid_value.value,
        MlxValueType::EnumArray(vec![
            Some("input".to_string()),
            Some("output".to_string()),
            Some("input".to_string())
        ])
    );

    let invalid_result = var.with(vec!["input", "invalid", "output"]);
    assert!(invalid_result.is_err());
    match invalid_result.unwrap_err() {
        MlxValueError::InvalidEnumArrayOption {
            position, value, ..
        } => {
            assert_eq!(position, 1);
            assert_eq!(value, "invalid");
        }
        _ => panic!("Expected InvalidEnumArrayOption error"),
    }
}

// test_sparse_enum_array_creation tests creating sparse enum arrays
// where some indices are unset (None).
#[test]
fn test_sparse_enum_array_creation() {
    let var = create_test_variable(
        "test_sparse_enum_array",
        MlxVariableSpec::EnumArray {
            options: vec![
                "input".to_string(),
                "output".to_string(),
                "bidirectional".to_string(),
            ],
            size: 4,
        },
    );

    // Vec<Option<String>> for sparse arrays
    let sparse_value = var
        .with(vec![
            Some("input".to_string()),
            None,
            Some("output".to_string()),
            None,
        ])
        .unwrap();

    assert_eq!(
        sparse_value.value,
        MlxValueType::EnumArray(vec![
            Some("input".to_string()),
            None,
            Some("output".to_string()),
            None
        ])
    );

    // Display should show "-" for None values
    let display = sparse_value.to_display_string();
    assert_eq!(display, "[input, -, output, -]");

    // Validation should still work for Some values
    let invalid_result = var.with(vec![
        Some("input".to_string()),
        Some("invalid".to_string()),
        None,
        None,
    ]);
    assert!(invalid_result.is_err());
}

// test_integer_array_creation tests creating integer arrays with sparse support.
#[test]
fn test_integer_array_creation() {
    let var = create_test_variable("test_int_array", MlxVariableSpec::IntegerArray { size: 3 });

    // Dense array (Vec<i64>) gets converted to sparse format
    let dense_value = var.with(vec![42i64, -123, 0]).unwrap();
    assert_eq!(
        dense_value.value,
        MlxValueType::IntegerArray(vec![Some(42), Some(-123), Some(0)])
    );

    // Sparse array (Vec<Option<i64>>)
    let sparse_value = var.with(vec![Some(42), None, Some(0)]).unwrap();
    assert_eq!(
        sparse_value.value,
        MlxValueType::IntegerArray(vec![Some(42), None, Some(0)])
    );

    // Display should show "-" for None values
    let display = sparse_value.to_display_string();
    assert_eq!(display, "[42, -, 0]");

    // Wrong size gets caught
    let invalid_result = var.with(vec![1i64, 2]);
    assert!(invalid_result.is_err());
}

// test_binary_array_creation tests creating binary arrays with sparse support.
#[test]
fn test_binary_array_creation() {
    let var = create_test_variable(
        "test_binary_array",
        MlxVariableSpec::BinaryArray { size: 2 },
    );

    // Dense array (Vec<Vec<u8>>) gets converted to sparse format
    let dense_value = var.with(vec![vec![0x1a, 0x2b], vec![0x3c, 0x4d]]).unwrap();
    assert_eq!(
        dense_value.value,
        MlxValueType::BinaryArray(vec![Some(vec![0x1a, 0x2b]), Some(vec![0x3c, 0x4d])])
    );

    // Sparse array (Vec<Option<Vec<u8>>>)
    let sparse_value = var.with(vec![Some(vec![0x1a, 0x2b]), None]).unwrap();
    assert_eq!(
        sparse_value.value,
        MlxValueType::BinaryArray(vec![Some(vec![0x1a, 0x2b]), None])
    );

    // Display should show count including sparse info
    let display = sparse_value.to_display_string();
    assert_eq!(display, "[2 binary values, 1 set]");
}

// test_type_mismatch makes sure we can't create a new variable
// value with an incorrect type by passing a bool to an integer
// variable spec.
#[test]
fn test_type_mismatch() {
    let var = create_test_variable("test_int", MlxVariableSpec::Integer);

    let result = var.with(true);
    assert!(result.is_err());
    match result.unwrap_err() {
        MlxValueError::TypeMismatch { expected, got } => {
            assert!(expected.contains("Integer"));
            assert!(got.contains("bool"));
        }
        _ => panic!("Expected TypeMismatch error"),
    }
}

// test_contextual_string_handling tests the same string input,
// and verifies different behavior based on spec.
#[test]
fn test_contextual_string_handling() {
    // String spec - just stores the string.
    let string_var = create_test_variable("test_string", MlxVariableSpec::String);
    let string_value = string_var.with("medium").unwrap();
    assert_eq!(
        string_value.value,
        MlxValueType::String("medium".to_string())
    );

    // Enum spec - validates against options.
    let enum_var = create_test_variable(
        "test_enum",
        MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        },
    );
    let enum_value = enum_var.with("medium").unwrap();
    assert_eq!(enum_value.value, MlxValueType::Enum("medium".to_string()));
}

// test_string_parsing_for_single_values is one big test
// that makes sure all of the string -> spec parsing works
// as expected. mlxconfig returns all values as strings when
// working with --json, so we need to make sure this works
// as part of deserializing the JSON payloads. This one is
// specifically for testing single values.
#[test]
fn test_string_parsing_for_single_values() {
    // Boolean parsing.
    let bool_var = create_test_variable("test_bool", MlxVariableSpec::Boolean);
    assert_eq!(
        bool_var.with("true".to_string()).unwrap().value,
        MlxValueType::Boolean(true)
    );
    assert_eq!(
        bool_var.with("1".to_string()).unwrap().value,
        MlxValueType::Boolean(true)
    );
    assert_eq!(
        bool_var.with("YES".to_string()).unwrap().value,
        MlxValueType::Boolean(true)
    );
    assert_eq!(
        bool_var.with("enabled".to_string()).unwrap().value,
        MlxValueType::Boolean(true)
    );
    assert_eq!(
        bool_var.with("on".to_string()).unwrap().value,
        MlxValueType::Boolean(true)
    );
    assert_eq!(
        bool_var.with("false".to_string()).unwrap().value,
        MlxValueType::Boolean(false)
    );
    assert_eq!(
        bool_var.with("0".to_string()).unwrap().value,
        MlxValueType::Boolean(false)
    );
    assert_eq!(
        bool_var.with("NO".to_string()).unwrap().value,
        MlxValueType::Boolean(false)
    );
    assert_eq!(
        bool_var.with("disabled".to_string()).unwrap().value,
        MlxValueType::Boolean(false)
    );
    assert_eq!(
        bool_var.with("off".to_string()).unwrap().value,
        MlxValueType::Boolean(false)
    );
    assert!(bool_var.with("maybe".to_string()).is_err());

    // Integer parsing.
    let int_var = create_test_variable("test_int", MlxVariableSpec::Integer);
    assert_eq!(
        int_var.with("42".to_string()).unwrap().value,
        MlxValueType::Integer(42)
    );
    assert_eq!(
        int_var.with("-123".to_string()).unwrap().value,
        MlxValueType::Integer(-123)
    );
    assert_eq!(
        int_var.with("0".to_string()).unwrap().value,
        MlxValueType::Integer(0)
    );
    assert!(int_var.with("not_a_number".to_string()).is_err());

    // String parsing (trivial but good to test).
    let str_var = create_test_variable("test_string", MlxVariableSpec::String);
    assert_eq!(
        str_var.with("hello world".to_string()).unwrap().value,
        MlxValueType::String("hello world".to_string())
    );
    assert_eq!(
        str_var.with("  trimmed  ".to_string()).unwrap().value,
        MlxValueType::String("trimmed".to_string())
    );

    // Enum parsing with validation.
    let enum_var = create_test_variable(
        "test_enum",
        MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        },
    );
    assert_eq!(
        enum_var.with("medium".to_string()).unwrap().value,
        MlxValueType::Enum("medium".to_string())
    );
    assert_eq!(
        enum_var.with("high".to_string()).unwrap().value,
        MlxValueType::Enum("high".to_string())
    );
    assert_eq!(
        enum_var.with(" low ".to_string()).unwrap().value,
        MlxValueType::Enum("low".to_string())
    ); // trimmed
    assert!(enum_var.with("invalid".to_string()).is_err());

    // Preset parsing.
    let preset_var =
        create_test_variable("test_preset", MlxVariableSpec::Preset { max_preset: 10 });
    assert_eq!(
        preset_var.with("5".to_string()).unwrap().value,
        MlxValueType::Preset(5)
    );
    assert_eq!(
        preset_var.with("0".to_string()).unwrap().value,
        MlxValueType::Preset(0)
    );
    assert_eq!(
        preset_var.with("10".to_string()).unwrap().value,
        MlxValueType::Preset(10)
    );
    assert!(preset_var.with("15".to_string()).is_err()); // out of range
    assert!(preset_var.with("not_a_number".to_string()).is_err());

    // Hex parsing for Binary, Bytes, and Opaque.
    let binary_var = create_test_variable("test_binary", MlxVariableSpec::Binary);
    let bytes_var = create_test_variable("test_bytes", MlxVariableSpec::Bytes);
    let opaque_var = create_test_variable("test_opaque", MlxVariableSpec::Opaque);

    assert_eq!(
        binary_var.with("0x1a2b3c".to_string()).unwrap().value,
        MlxValueType::Binary(vec![0x1a, 0x2b, 0x3c])
    );
    assert_eq!(
        bytes_var.with("1a2b3c".to_string()).unwrap().value,
        MlxValueType::Bytes(vec![0x1a, 0x2b, 0x3c])
    );
    assert_eq!(
        opaque_var.with("0X1A2B3C".to_string()).unwrap().value,
        MlxValueType::Opaque(vec![0x1a, 0x2b, 0x3c])
    );
    assert!(binary_var.with("not_hex".to_string()).is_err());

    // Test that single strings reject array specs.
    let bool_array_var =
        create_test_variable("test_bool_array", MlxVariableSpec::BooleanArray { size: 3 });
    assert!(bool_array_var.with("true".to_string()).is_err());
}

// test_vec_string_parsing_for_array_values is one big test
// that makes sure all of the string -> spec parsing works
// as expected. mlxconfig returns all values as strings when
// working with --json, so we need to make sure this works
// as part of deserializing the JSON payloads. This one is
// specifically for testing arrays, including sparse array support.
#[test]
fn test_vec_string_parsing_for_array_values() {
    // Generic string array.
    let array_var = create_test_variable("test_array", MlxVariableSpec::Array);
    let result = array_var
        .with(vec![
            "hello".to_string(),
            " world ".to_string(),
            "test".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::Array(vec![
            "hello".to_string(),
            "world".to_string(),
            "test".to_string()
        ])
    ); // trimmed

    // Boolean array parsing with sparse support.
    let bool_array_var =
        create_test_variable("test_bool_array", MlxVariableSpec::BooleanArray { size: 4 });

    // Dense array
    let result = bool_array_var
        .with(vec![
            "true".to_string(),
            "0".to_string(),
            "YES".to_string(),
            "disabled".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::BooleanArray(vec![Some(true), Some(false), Some(true), Some(false)])
    );

    // Sparse array with "-" notation
    let sparse_result = bool_array_var
        .with(vec![
            "true".to_string(),
            "-".to_string(),
            "false".to_string(),
            "".to_string(), // empty string also means None
        ])
        .unwrap();
    assert_eq!(
        sparse_result.value,
        MlxValueType::BooleanArray(vec![Some(true), None, Some(false), None])
    );

    // Wrong size.
    assert!(
        bool_array_var
            .with(vec!["true".to_string(), "false".to_string()])
            .is_err()
    );

    // Invalid boolean in array.
    assert!(
        bool_array_var
            .with(vec![
                "true".to_string(),
                "maybe".to_string(),
                "false".to_string(),
                "true".to_string()
            ])
            .is_err()
    );

    // Integer array parsing with sparse support.
    let int_array_var =
        create_test_variable("test_int_array", MlxVariableSpec::IntegerArray { size: 3 });

    // Dense array
    let result = int_array_var
        .with(vec!["42".to_string(), "-123".to_string(), "0".to_string()])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::IntegerArray(vec![Some(42), Some(-123), Some(0)])
    );

    // Sparse array with "-" notation
    let sparse_result = int_array_var
        .with(vec!["42".to_string(), "-".to_string(), "0".to_string()])
        .unwrap();
    assert_eq!(
        sparse_result.value,
        MlxValueType::IntegerArray(vec![Some(42), None, Some(0)])
    );

    // Wrong size.
    assert!(
        int_array_var
            .with(vec!["1".to_string(), "2".to_string()])
            .is_err()
    );

    // Invalid integer in array.
    assert!(
        int_array_var
            .with(vec![
                "42".to_string(),
                "not_a_number".to_string(),
                "0".to_string()
            ])
            .is_err()
    );

    // Enum array parsing with sparse support.
    let enum_array_var = create_test_variable(
        "test_enum_array",
        MlxVariableSpec::EnumArray {
            options: vec![
                "input".to_string(),
                "output".to_string(),
                "bidirectional".to_string(),
            ],
            size: 4,
        },
    );

    // Dense array
    let result = enum_array_var
        .with(vec![
            "input".to_string(),
            " output ".to_string(),
            "bidirectional".to_string(),
            "input".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::EnumArray(vec![
            Some("input".to_string()),
            Some("output".to_string()),
            Some("bidirectional".to_string()),
            Some("input".to_string())
        ])
    );

    // Sparse array with "-" notation
    let sparse_result = enum_array_var
        .with(vec![
            "input".to_string(),
            "-".to_string(),
            "output".to_string(),
            "".to_string(), // empty string also means None
        ])
        .unwrap();
    assert_eq!(
        sparse_result.value,
        MlxValueType::EnumArray(vec![
            Some("input".to_string()),
            None,
            Some("output".to_string()),
            None
        ])
    );

    // Wrong size.
    assert!(
        enum_array_var
            .with(vec!["input".to_string(), "output".to_string()])
            .is_err()
    );

    // Invalid enum option in array.
    let result = enum_array_var.with(vec![
        "input".to_string(),
        "invalid".to_string(),
        "output".to_string(),
        "input".to_string(),
    ]);
    assert!(result.is_err());
    match result.unwrap_err() {
        MlxValueError::InvalidEnumArrayOption {
            position,
            value,
            allowed,
        } => {
            assert_eq!(position, 1);
            assert_eq!(value, "invalid");
            assert_eq!(allowed, vec!["input", "output", "bidirectional"]);
        }
        _ => panic!("Expected InvalidEnumArrayOption error"),
    }

    // Binary array parsing with sparse support.
    let binary_array_var = create_test_variable(
        "test_binary_array",
        MlxVariableSpec::BinaryArray { size: 3 },
    );

    // Dense array
    let result = binary_array_var
        .with(vec![
            "0x1a2b".to_string(),
            "3c4d".to_string(),
            " 0X5E6F ".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::BinaryArray(vec![
            Some(vec![0x1a, 0x2b]),
            Some(vec![0x3c, 0x4d]),
            Some(vec![0x5e, 0x6f])
        ])
    );

    // Sparse array with "-" notation
    let sparse_result = binary_array_var
        .with(vec![
            "0x1a2b".to_string(),
            "-".to_string(),
            "3c4d".to_string(),
        ])
        .unwrap();
    assert_eq!(
        sparse_result.value,
        MlxValueType::BinaryArray(vec![Some(vec![0x1a, 0x2b]), None, Some(vec![0x3c, 0x4d])])
    );

    // Wrong size.
    assert!(
        binary_array_var
            .with(vec!["0x1a2b".to_string(), "3c4d".to_string()])
            .is_err()
    );

    // Invalid hex in array.
    assert!(
        binary_array_var
            .with(vec![
                "0x1a2b".to_string(),
                "invalid".to_string(),
                "3c4d".to_string()
            ])
            .is_err()
    );

    // Test that array types reject single value specs.
    let string_var = create_test_variable("test_string", MlxVariableSpec::String);
    assert!(
        string_var
            .with(vec!["hello".to_string(), "world".to_string()])
            .is_err()
    );

    let enum_var = create_test_variable(
        "test_enum",
        MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "high".to_string()],
        },
    );
    assert!(
        enum_var
            .with(vec!["low".to_string(), "high".to_string()])
            .is_err()
    );
}

// test_sparse_array_validation tests that sparse arrays properly validate
// their Some values while ignoring None values.
#[test]
fn test_sparse_array_validation() {
    // Test enum array validation with sparse values
    let enum_array_var = create_test_variable(
        "test_sparse_validation",
        MlxVariableSpec::EnumArray {
            options: vec!["valid1".to_string(), "valid2".to_string()],
            size: 3,
        },
    );

    // Valid sparse array - None values should be ignored during validation
    let valid_sparse = enum_array_var
        .with(vec![
            Some("valid1".to_string()),
            None,
            Some("valid2".to_string()),
        ])
        .unwrap();

    assert_eq!(
        valid_sparse.value,
        MlxValueType::EnumArray(vec![
            Some("valid1".to_string()),
            None,
            Some("valid2".to_string())
        ])
    );

    // Invalid sparse array - Some values still need to be validated
    let invalid_sparse = enum_array_var.with(vec![
        Some("valid1".to_string()),
        None,
        Some("invalid".to_string()),
    ]);

    assert!(invalid_sparse.is_err());
    match invalid_sparse.unwrap_err() {
        MlxValueError::InvalidEnumArrayOption {
            position, value, ..
        } => {
            assert_eq!(position, 2);
            assert_eq!(value, "invalid");
        }
        _ => panic!("Expected InvalidEnumArrayOption error"),
    }
}

// test_display_formatting_sparse_arrays tests that sparse arrays display
// correctly with "-" for None values.
#[test]
fn test_display_formatting_sparse_arrays() {
    // Boolean array display
    let bool_var = create_test_variable(
        "test_bool_display",
        MlxVariableSpec::BooleanArray { size: 3 },
    );
    let bool_value = bool_var.with(vec![Some(true), None, Some(false)]).unwrap();
    assert_eq!(bool_value.to_display_string(), "[true, -, false]");

    // Integer array display
    let int_var = create_test_variable(
        "test_int_display",
        MlxVariableSpec::IntegerArray { size: 4 },
    );
    let int_value = int_var.with(vec![Some(42), None, Some(-10), None]).unwrap();
    assert_eq!(int_value.to_display_string(), "[42, -, -10, -]");

    // Enum array display
    let enum_var = create_test_variable(
        "test_enum_display",
        MlxVariableSpec::EnumArray {
            options: vec!["option1".to_string(), "option2".to_string()],
            size: 3,
        },
    );
    let enum_value = enum_var
        .with(vec![
            Some("option1".to_string()),
            None,
            Some("option2".to_string()),
        ])
        .unwrap();
    assert_eq!(enum_value.to_display_string(), "[option1, -, option2]");

    // Binary array display shows count information
    let binary_var = create_test_variable(
        "test_binary_display",
        MlxVariableSpec::BinaryArray { size: 4 },
    );
    let binary_value = binary_var
        .with(vec![Some(vec![0x1a]), None, Some(vec![0x2b, 0x3c]), None])
        .unwrap();
    assert_eq!(binary_value.to_display_string(), "[4 binary values, 2 set]");
}

// test_mixed_dense_and_sparse_operations tests that we can work with both
// dense arrays (automatically converted to sparse) and explicit sparse arrays.
#[test]
fn test_mixed_dense_and_sparse_operations() {
    let bool_var = create_test_variable("test_mixed", MlxVariableSpec::BooleanArray { size: 3 });

    // Dense input - gets converted to sparse internally
    let dense_value = bool_var.with(vec![true, false, true]).unwrap();
    assert_eq!(
        dense_value.value,
        MlxValueType::BooleanArray(vec![Some(true), Some(false), Some(true)])
    );

    // Sparse input - used directly
    let sparse_value = bool_var.with(vec![Some(true), None, Some(true)]).unwrap();
    assert_eq!(
        sparse_value.value,
        MlxValueType::BooleanArray(vec![Some(true), None, Some(true)])
    );

    // Both should display properly
    assert_eq!(dense_value.to_display_string(), "[true, false, true]");
    assert_eq!(sparse_value.to_display_string(), "[true, -, true]");
}

#[test]
fn test_is_array_type_boolean_array() {
    let array_value = MlxValueType::BooleanArray(vec![Some(true), None, Some(false)]);
    assert!(array_value.is_array_type());
}

#[test]
fn test_is_array_type_integer_array() {
    let array_value = MlxValueType::IntegerArray(vec![Some(42), None, Some(100)]);
    assert!(array_value.is_array_type());
}

#[test]
fn test_is_array_type_enum_array() {
    let array_value = MlxValueType::EnumArray(vec![
        Some("option1".to_string()),
        None,
        Some("option2".to_string()),
    ]);
    assert!(array_value.is_array_type());
}

#[test]
fn test_is_array_type_binary_array() {
    let array_value =
        MlxValueType::BinaryArray(vec![Some(vec![0x01, 0x02]), None, Some(vec![0x03, 0x04])]);
    assert!(array_value.is_array_type());
}

#[test]
fn test_is_array_type_non_arrays() {
    let test_cases = vec![
        MlxValueType::Boolean(true),
        MlxValueType::Integer(42),
        MlxValueType::String("test".to_string()),
        MlxValueType::Enum("option".to_string()),
        MlxValueType::Preset(5),
        MlxValueType::Binary(vec![0x01, 0x02]),
        MlxValueType::Bytes(vec![0x01, 0x02]),
        MlxValueType::Array(vec!["item1".to_string(), "item2".to_string()]),
        MlxValueType::Opaque(vec![0x01, 0x02]),
    ];

    for value in test_cases {
        assert!(
            !value.is_array_type(),
            "Expected {value:?} to not be an array type",
        );
    }
}

#[test]
fn test_get_set_indices_boolean_array() {
    let array_value = MlxValueType::BooleanArray(vec![
        Some(true),  // index 0
        None,        // index 1 - not set
        Some(false), // index 2
        None,        // index 3 - not set
        Some(true),  // index 4
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0, 2, 4]);
}

#[test]
fn test_get_set_indices_integer_array() {
    let array_value = MlxValueType::IntegerArray(vec![
        None,      // index 0 - not set
        Some(42),  // index 1
        Some(100), // index 2
        None,      // index 3 - not set
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![1, 2]);
}

#[test]
fn test_get_set_indices_enum_array() {
    let array_value = MlxValueType::EnumArray(vec![
        Some("option1".to_string()), // index 0
        Some("option2".to_string()), // index 1
        None,                        // index 2 - not set
        Some("option3".to_string()), // index 3
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0, 1, 3]);
}

#[test]
fn test_get_set_indices_binary_array() {
    let array_value = MlxValueType::BinaryArray(vec![
        Some(vec![0x01, 0x02]), // index 0
        None,                   // index 1 - not set
        None,                   // index 2 - not set
        Some(vec![0x03, 0x04]), // index 3
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0, 3]);
}

#[test]
fn test_get_set_indices_all_none() {
    let array_value = MlxValueType::BooleanArray(vec![None, None, None]);
    let indices = array_value.get_set_indices().unwrap();
    assert!(indices.is_empty());
}

#[test]
fn test_get_set_indices_all_some() {
    let array_value = MlxValueType::IntegerArray(vec![Some(1), Some(2), Some(3), Some(4)]);
    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}

#[test]
fn test_get_set_indices_empty_array() {
    let array_value = MlxValueType::BooleanArray(vec![]);
    let indices = array_value.get_set_indices().unwrap();
    assert!(indices.is_empty());
}

#[test]
fn test_get_set_indices_single_element() {
    let array_value = MlxValueType::EnumArray(vec![Some("only_option".to_string())]);
    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0]);
}

#[test]
fn test_get_set_indices_non_array_returns_none() {
    let test_cases = vec![
        MlxValueType::Boolean(true),
        MlxValueType::Integer(42),
        MlxValueType::String("test".to_string()),
        MlxValueType::Enum("option".to_string()),
        MlxValueType::Preset(5),
        MlxValueType::Binary(vec![0x01, 0x02]),
        MlxValueType::Bytes(vec![0x01, 0x02]),
        MlxValueType::Array(vec!["item1".to_string(), "item2".to_string()]),
        MlxValueType::Opaque(vec![0x01, 0x02]),
    ];

    for value in test_cases {
        assert!(
            value.get_set_indices().is_none(),
            "Expected {value:?} to return None for get_set_indices",
        );
    }
}

#[test]
fn test_get_set_indices_sparse_pattern() {
    // Test a realistic sparse array pattern
    let array_value = MlxValueType::EnumArray(vec![
        Some("HOST_0".to_string()), // index 0 - set
        None,                       // index 1 - not set
        None,                       // index 2 - not set
        Some("HOST_3".to_string()), // index 3 - set
        None,                       // index 4 - not set
        None,                       // index 5 - not set
        Some("HOST_6".to_string()), // index 6 - set
        None,                       // index 7 - not set
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![0, 3, 6]);
}

#[test]
fn test_get_set_indices_maintains_order() {
    // Ensure indices are returned in ascending order
    let array_value = MlxValueType::IntegerArray(vec![
        None,     // index 0
        Some(10), // index 1
        None,     // index 2
        Some(30), // index 3
        None,     // index 4
        Some(50), // index 5
    ]);

    let indices = array_value.get_set_indices().unwrap();
    assert_eq!(indices, vec![1, 3, 5]);

    // Verify they're in ascending order
    for window in indices.windows(2) {
        assert!(
            window[0] < window[1],
            "Indices should be in ascending order"
        );
    }
}
