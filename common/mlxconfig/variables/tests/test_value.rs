/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use mlxconfig_variables::{MlxConfigVariable, MlxValueError, MlxValueType, MlxVariableSpec};

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

    // Vec<bool> gets automatically validated for size.
    let valid_value = var.with(vec![true, false, true, false]).unwrap();
    assert_eq!(
        valid_value.value,
        MlxValueType::BooleanArray(vec![true, false, true, false])
    );

    // Wrong size gets caught.
    let invalid_result = var.with(vec![true, false]);
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
            "input".to_string(),
            "output".to_string(),
            "input".to_string()
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

// test_contextual_string_handling tests the ame string input,
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
// specifically for testing arrays.
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

    // Boolean array parsing.
    let bool_array_var =
        create_test_variable("test_bool_array", MlxVariableSpec::BooleanArray { size: 4 });
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
        MlxValueType::BooleanArray(vec![true, false, true, false])
    );

    // Wrong size.
    assert!(bool_array_var
        .with(vec!["true".to_string(), "false".to_string()])
        .is_err());

    // Invalid boolean in array.
    assert!(bool_array_var
        .with(vec![
            "true".to_string(),
            "maybe".to_string(),
            "false".to_string(),
            "true".to_string()
        ])
        .is_err());

    // Integer array parsing.
    let int_array_var =
        create_test_variable("test_int_array", MlxVariableSpec::IntegerArray { size: 3 });
    let result = int_array_var
        .with(vec!["42".to_string(), "-123".to_string(), "0".to_string()])
        .unwrap();
    assert_eq!(result.value, MlxValueType::IntegerArray(vec![42, -123, 0]));

    // Wrong size.
    assert!(int_array_var
        .with(vec!["1".to_string(), "2".to_string()])
        .is_err());

    // Invalid integer in array.
    assert!(int_array_var
        .with(vec![
            "42".to_string(),
            "not_a_number".to_string(),
            "0".to_string()
        ])
        .is_err());

    // Enum array parsing.
    let enum_array_var = create_test_variable(
        "test_enum_array",
        MlxVariableSpec::EnumArray {
            options: vec![
                "input".to_string(),
                "output".to_string(),
                "bidirectional".to_string(),
            ],
            size: 3,
        },
    );
    let result = enum_array_var
        .with(vec![
            "input".to_string(),
            " output ".to_string(),
            "bidirectional".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::EnumArray(vec![
            "input".to_string(),
            "output".to_string(),
            "bidirectional".to_string()
        ])
    );

    // Wrong size.
    assert!(enum_array_var
        .with(vec!["input".to_string(), "output".to_string()])
        .is_err());

    // Invalid enum option in array.
    let result = enum_array_var.with(vec![
        "input".to_string(),
        "invalid".to_string(),
        "output".to_string(),
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

    // Binary array parsing.
    let binary_array_var = create_test_variable(
        "test_binary_array",
        MlxVariableSpec::BinaryArray { size: 3 },
    );
    let result = binary_array_var
        .with(vec![
            "0x1a2b".to_string(),
            "3c4d".to_string(),
            " 0X5E6F ".to_string(),
        ])
        .unwrap();
    assert_eq!(
        result.value,
        MlxValueType::BinaryArray(vec![vec![0x1a, 0x2b], vec![0x3c, 0x4d], vec![0x5e, 0x6f]])
    );

    // Wrong size.
    assert!(binary_array_var
        .with(vec!["0x1a2b".to_string(), "3c4d".to_string()])
        .is_err());

    // Invalid hex in array.
    assert!(binary_array_var
        .with(vec![
            "0x1a2b".to_string(),
            "invalid".to_string(),
            "3c4d".to_string()
        ])
        .is_err());

    // Test that array types reject single value specs.
    let string_var = create_test_variable("test_string", MlxVariableSpec::String);
    assert!(string_var
        .with(vec!["hello".to_string(), "world".to_string()])
        .is_err());

    let enum_var = create_test_variable(
        "test_enum",
        MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "high".to_string()],
        },
    );
    assert!(enum_var
        .with(vec!["low".to_string(), "high".to_string()])
        .is_err());
}
