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

// tests/errors.rs
// Unit tests for error handling throughout the MQTT client library including
// error creation, categorization, and proper error propagation.

use mqttea::errors::{MqtteaClientError, unregistered_type_error};
use prost::DecodeError;
use rumqttc::{ClientError, Disconnect, Request};

// Helper functions to create test errors
fn create_test_connection_error() -> ClientError {
    // Create a mock connection error using Request variant (only 2 variants exist in rumqttc 0.24)
    ClientError::Request(Request::Disconnect(Disconnect))
}

fn create_test_decode_error() -> DecodeError {
    DecodeError::new("Test protobuf decode error")
}

fn create_test_json_error() -> serde_json::Error {
    serde_json::from_str::<i32>("not a number").unwrap_err()
}

fn create_test_yaml_error() -> serde_yaml::Error {
    serde_yaml::from_str::<i32>("{ invalid: yaml: }}}").unwrap_err()
}

// Tests for error creation and conversion
#[test]
fn test_connection_error_from_client_error() {
    let client_error = create_test_connection_error();
    let mqtt_error = MqtteaClientError::from(client_error);

    match mqtt_error {
        MqtteaClientError::ConnectionError(_) => {} // Expected
        _ => panic!("Should be ConnectionError"),
    }

    assert!(mqtt_error.is_connection_error());
    assert!(!mqtt_error.is_deserialization_error());
    assert!(!mqtt_error.is_serialization_error());
}

#[test]
fn test_protobuf_deserialization_error() {
    let decode_error = create_test_decode_error();
    let mqtt_error = MqtteaClientError::from(decode_error);

    match mqtt_error {
        MqtteaClientError::ProtobufDeserializationError(_) => {} // Expected
        _ => panic!("Should be ProtobufDeserializationError"),
    }

    assert!(mqtt_error.is_deserialization_error());
    assert!(!mqtt_error.is_connection_error());
    assert!(!mqtt_error.is_serialization_error());
}

#[test]
fn test_json_serialization_error() {
    let json_error = create_test_json_error();
    let mqtt_error = MqtteaClientError::from(json_error);

    match mqtt_error {
        MqtteaClientError::JsonSerializationError(_) => {} // Expected
        _ => panic!("Should be JsonSerializationError"),
    }

    assert!(mqtt_error.is_serialization_error());
    assert!(!mqtt_error.is_connection_error());
    assert!(!mqtt_error.is_deserialization_error());
}

#[test]
fn test_yaml_serialization_error() {
    let yaml_error = create_test_yaml_error();
    let mqtt_error = MqtteaClientError::from(yaml_error);

    match mqtt_error {
        MqtteaClientError::YamlSerializationError(_) => {} // Expected
        _ => panic!("Should be YamlSerializationError"),
    }

    assert!(mqtt_error.is_serialization_error());
}

// Tests for convenience error constructors
#[test]
fn test_unknown_message_type_constructor() {
    let error = MqtteaClientError::unknown_message_type("/pets/fluffy/unknown-data");

    match error {
        MqtteaClientError::UnknownMessageType(ref topic) => {
            assert_eq!(topic, "/pets/fluffy/unknown-data");
        }
        _ => panic!("Should be UnknownMessageType"),
    }

    assert!(error.is_topic_error());
}

#[test]
fn test_topic_parsing_error_constructor() {
    let error = MqtteaClientError::topic_parsing_error("Invalid topic format for hamster data");

    match error {
        MqtteaClientError::TopicParsingError(ref msg) => {
            assert_eq!(msg, "Invalid topic format for hamster data");
        }
        _ => panic!("Should be TopicParsingError"),
    }

    assert!(error.is_topic_error());
}

#[test]
fn test_raw_message_error_constructor() {
    let error = MqtteaClientError::raw_message_error("Failed to process bird song data");

    match error {
        MqtteaClientError::RawMessageError(msg) => {
            assert_eq!(msg, "Failed to process bird song data");
        }
        _ => panic!("Should be RawMessageError"),
    }
}

#[test]
fn test_unregistered_type_constructor() {
    let error = MqtteaClientError::unregistered_type("CatMessage");

    match error {
        MqtteaClientError::UnregisteredType(ref type_name) => {
            assert_eq!(type_name, "CatMessage");
        }
        _ => panic!("Should be UnregisteredType"),
    }

    assert!(error.is_registry_error());
}

#[test]
fn test_invalid_utf8_constructor() {
    let error = MqtteaClientError::invalid_utf8("Invalid UTF-8 in dog collar message");

    match error {
        MqtteaClientError::InvalidUtf8(msg) => {
            assert_eq!(msg, "Invalid UTF-8 in dog collar message");
        }
        _ => panic!("Should be InvalidUtf8"),
    }
}

#[test]
fn test_pattern_compilation_error_constructor() {
    let error = MqtteaClientError::pattern_compilation_error("Invalid regex: [unclosed bracket");

    match error {
        MqtteaClientError::PatternCompilationError(ref msg) => {
            assert_eq!(msg, "Invalid regex: [unclosed bracket");
        }
        _ => panic!("Should be PatternCompilationError"),
    }

    assert!(error.is_registry_error());
}

// Tests for error categorization methods
#[test]
fn test_error_categorization_connection() {
    let connection_error = MqtteaClientError::ConnectionError(create_test_connection_error());

    assert!(connection_error.is_connection_error());
    assert!(!connection_error.is_deserialization_error());
    assert!(!connection_error.is_serialization_error());
    assert!(!connection_error.is_topic_error());
    assert!(!connection_error.is_registry_error());
}

#[test]
fn test_error_categorization_deserialization() {
    let protobuf_error =
        MqtteaClientError::ProtobufDeserializationError(create_test_decode_error());
    let json_error = MqtteaClientError::JsonDeserializationError(create_test_json_error());
    let yaml_error = MqtteaClientError::YamlDeserializationError(create_test_yaml_error());

    assert!(protobuf_error.is_deserialization_error());
    assert!(json_error.is_deserialization_error());
    assert!(yaml_error.is_deserialization_error());

    assert!(!protobuf_error.is_connection_error());
    assert!(!json_error.is_serialization_error());
    assert!(!yaml_error.is_topic_error());
}

#[test]
fn test_error_categorization_serialization() {
    let json_error = MqtteaClientError::JsonSerializationError(create_test_json_error());
    let yaml_error = MqtteaClientError::YamlSerializationError(create_test_yaml_error());

    assert!(json_error.is_serialization_error());
    assert!(yaml_error.is_serialization_error());

    assert!(!json_error.is_connection_error());
    assert!(!yaml_error.is_topic_error());
}

#[test]
fn test_error_categorization_topic() {
    let unknown_type = MqtteaClientError::unknown_message_type("/pets/lizard/unknown");
    let parsing_error = MqtteaClientError::topic_parsing_error("Bad topic format");

    assert!(unknown_type.is_topic_error());
    assert!(parsing_error.is_topic_error());

    assert!(!unknown_type.is_connection_error());
    assert!(!parsing_error.is_serialization_error());
}

#[test]
fn test_error_categorization_registry() {
    let unregistered = MqtteaClientError::unregistered_type("UnknownType");
    let pattern_error = MqtteaClientError::pattern_compilation_error("Bad regex");

    assert!(unregistered.is_registry_error());
    assert!(pattern_error.is_registry_error());

    assert!(!unregistered.is_topic_error());
    assert!(!pattern_error.is_connection_error());
}

// Tests for error display and formatting
#[test]
fn test_error_display_connection() {
    let error = MqtteaClientError::ConnectionError(create_test_connection_error());
    let display = format!("{error}");

    assert!(display.contains("MQTT connection error"));
    // Note: Specific error message depends on rumqttc internals
}

#[test]
fn test_error_display_unknown_message_type() {
    let error = MqtteaClientError::unknown_message_type("/pets/parrot/songs");
    let display = format!("{error}");

    assert!(display.contains("Unknown message type"));
    assert!(display.contains("/pets/parrot/songs"));
}

#[test]
fn test_error_display_topic_parsing() {
    let error = MqtteaClientError::topic_parsing_error("Topic must start with /");
    let display = format!("{error}");

    assert!(display.contains("Topic parsing error"));
    assert!(display.contains("Topic must start with /"));
}

#[test]
fn test_error_display_raw_message() {
    let error = MqtteaClientError::raw_message_error("Failed to decode turtle sensor data");
    let display = format!("{error}");

    assert!(display.contains("Raw message error"));
    assert!(display.contains("turtle sensor data"));
}

#[test]
fn test_error_display_unregistered_type() {
    let error = MqtteaClientError::unregistered_type("FishMessage");
    let display = format!("{error}");

    assert!(display.contains("Type not registered"));
    assert!(display.contains("FishMessage"));
}

#[test]
fn test_error_display_invalid_utf8() {
    let error = MqtteaClientError::invalid_utf8("Contains invalid UTF-8 bytes");
    let display = format!("{error}");

    assert!(display.contains("Invalid UTF-8"));
    assert!(display.contains("invalid UTF-8 bytes"));
}

#[test]
fn test_error_display_pattern_compilation() {
    let error = MqtteaClientError::pattern_compilation_error("Missing closing bracket in regex");
    let display = format!("{error}");

    assert!(display.contains("Pattern compilation error"));
    assert!(display.contains("closing bracket"));
}

// Tests for error debug formatting
#[test]
fn test_error_debug_format() {
    let error = MqtteaClientError::unknown_message_type("/debug/test");
    let debug = format!("{error:?}");

    assert!(debug.contains("UnknownMessageType"));
    assert!(debug.contains("/debug/test"));
}

// Tests for unregistered_type_error helper function
#[test]
fn test_unregistered_type_error_function() {
    let error = unregistered_type_error::<String>();

    match error {
        MqtteaClientError::UnregisteredType(type_name) => {
            assert!(type_name.contains("String"));
        }
        _ => panic!("Should be UnregisteredType"),
    }
}

#[test]
fn test_unregistered_type_error_custom_type() {
    #[derive(Debug)]
    struct CustomAnimalMessage;

    let error = unregistered_type_error::<CustomAnimalMessage>();

    match error {
        MqtteaClientError::UnregisteredType(type_name) => {
            assert!(type_name.contains("CustomAnimalMessage"));
        }
        _ => panic!("Should be UnregisteredType"),
    }
}

// Tests for error chaining and source
#[test]
fn test_error_source_connection() {
    let client_error = create_test_connection_error();
    let mqtt_error = MqtteaClientError::from(client_error);

    // Should have a source error
    assert!(std::error::Error::source(&mqtt_error).is_some());
}

#[test]
fn test_error_source_protobuf() {
    let decode_error = create_test_decode_error();
    let mqtt_error = MqtteaClientError::from(decode_error);

    // Should have a source error
    assert!(std::error::Error::source(&mqtt_error).is_some());
}

// Tests for error equality and comparison (for test assertions)
#[test]
fn test_error_equality() {
    let error1 = MqtteaClientError::unknown_message_type("/pets/cat/data");
    let error2 = MqtteaClientError::unknown_message_type("/pets/cat/data");
    let error3 = MqtteaClientError::unknown_message_type("/pets/dog/data");

    // Note: MqtteaClientError likely doesn't implement PartialEq due to inner error types
    // So we test by matching patterns instead
    match (&error1, &error2, &error3) {
        (
            MqtteaClientError::UnknownMessageType(t1),
            MqtteaClientError::UnknownMessageType(t2),
            MqtteaClientError::UnknownMessageType(t3),
        ) => {
            assert_eq!(t1, t2);
            assert_ne!(t1, t3);
        }
        _ => panic!("All should be UnknownMessageType"),
    }
}

// Tests for error default implementation
#[test]
fn test_error_default() {
    let default_error = MqtteaClientError::default();

    match default_error {
        MqtteaClientError::UnregisteredType(type_name) => {
            assert_eq!(type_name, "unknown");
        }
        _ => panic!("Should be default UnregisteredType"),
    }
}

// Test error with owned values to avoid borrow issues
#[test]
fn test_error_display_with_owned_values() {
    let error = MqtteaClientError::unknown_message_type("/pets/fluffy/unknown-data");

    // Test that we can format the error without borrowing issues
    let display = format!("{error}");
    assert!(display.contains("Unknown message type"));
    assert!(display.contains("/pets/fluffy/unknown-data"));

    // Test that we can still use the error after formatting
    match error {
        MqtteaClientError::UnknownMessageType(ref topic) => {
            assert_eq!(topic, "/pets/fluffy/unknown-data");
        }
        _ => panic!("Should be UnknownMessageType"),
    }
}

// Tests for JSON deserialization error creation
#[test]
fn test_json_deserialization_error_creation() {
    let json_result: Result<i32, _> = serde_json::from_str("invalid json");
    assert!(json_result.is_err());

    let json_error = json_result.unwrap_err();

    // Convert to our MQTT error
    let mqtt_error = MqtteaClientError::JsonDeserializationError(json_error);

    // Verify properties
    assert!(mqtt_error.is_deserialization_error());

    let display = format!("{mqtt_error}");
    assert!(display.contains("JSON deserialization error"));
}

// Tests for YAML deserialization error creation
#[test]
fn test_yaml_deserialization_error_creation() {
    let yaml_result: Result<i32, _> = serde_yaml::from_str("{ invalid: yaml: }}}");
    assert!(yaml_result.is_err());

    let yaml_error = yaml_result.unwrap_err();

    // Convert to our MQTT error
    let mqtt_error = MqtteaClientError::YamlDeserializationError(yaml_error);

    // Verify properties
    assert!(mqtt_error.is_deserialization_error());

    let display = format!("{mqtt_error}");
    assert!(display.contains("YAML deserialization error"));
}

// Performance test - error creation should be fast
#[test]
fn test_error_creation_performance() {
    let start = std::time::Instant::now();

    // Create many errors quickly
    for i in 0..10_000 {
        let _error = MqtteaClientError::unknown_message_type(format!("/pets/animal-{i}/data"));
    }

    let elapsed = start.elapsed();

    // Error creation should be very fast
    assert!(elapsed.as_millis() < 100, "Error creation should be fast");
}

// Test error with very long messages (edge case)
#[test]
fn test_error_with_long_message() {
    let long_topic = "/pets/".to_string() + &"a".repeat(10_000) + "/data";
    let error = MqtteaClientError::unknown_message_type(long_topic.clone());

    match error {
        MqtteaClientError::UnknownMessageType(ref topic) => {
            assert_eq!(topic.len(), long_topic.len());
            assert!(topic.starts_with("/pets/aa"));
            assert!(topic.ends_with("/data"));
        }
        _ => panic!("Should be UnknownMessageType"),
    }

    // Should be able to display even very long errors
    let display = format!("{error}");
    assert!(display.len() > 1000);
}

// Test error with special characters
#[test]
fn test_error_with_special_characters() {
    let special_topic = "/pets/🐱/data/emoji-test";
    let error = MqtteaClientError::unknown_message_type(special_topic);

    let display = format!("{error}");
    assert!(display.contains("🐱"));
    assert!(display.contains("emoji-test"));
}

// Test error Send + Sync traits (important for async code)
#[test]
fn test_error_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<MqtteaClientError>();
    assert_sync::<MqtteaClientError>();
}

// Test that errors can be used in Results and Options
#[test]
fn test_error_in_result() {
    fn might_fail(should_fail: bool) -> Result<String, MqtteaClientError> {
        if should_fail {
            Err(MqtteaClientError::unknown_message_type(
                "/pets/ferret/unknown",
            ))
        } else {
            Ok("success".to_string())
        }
    }

    let success = might_fail(false);
    assert!(success.is_ok());
    assert_eq!(success.unwrap(), "success");

    let failure = might_fail(true);
    assert!(failure.is_err());
    assert!(failure.unwrap_err().is_topic_error());
}

#[test]
fn test_error_in_option() {
    fn maybe_error(include_error: bool) -> Option<MqtteaClientError> {
        if include_error {
            Some(MqtteaClientError::raw_message_error(
                "Chinchilla sensor malfunction",
            ))
        } else {
            None
        }
    }

    assert!(maybe_error(false).is_none());

    let error_opt = maybe_error(true);
    assert!(error_opt.is_some());

    let error = error_opt.unwrap();
    match error {
        MqtteaClientError::RawMessageError(msg) => {
            assert!(msg.contains("Chinchilla"));
        }
        _ => panic!("Should be RawMessageError"),
    }
}
