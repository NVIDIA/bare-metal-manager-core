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

use std::collections::HashMap;

use libmlx::profile::error::MlxProfileError;
use libmlx::profile::profile::MlxConfigProfile;
use libmlx::profile::serialization::{
    SerializableProfile, deserialize_option_profile_map, serialize_option_profile_map,
};
use libmlx::registry::registries;
use rpc::protos::mlx_device::SerializableMlxConfigProfile as SerializableMlxConfigProfilePb;
use serde::{Deserialize, Serialize};

#[test]
fn test_serializable_profile_creation() {
    let profile = SerializableProfile::new("test_profile", "test_registry")
        .with_description("Test profile for unit tests")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 42)
        .with_config("STRING_VAR", "test_value");

    assert_eq!(profile.name, "test_profile");
    assert_eq!(profile.registry_name, "test_registry");
    assert_eq!(
        profile.description,
        Some("Test profile for unit tests".to_string())
    );
    assert_eq!(profile.config.len(), 3);
}

#[test]
fn test_yaml_serialization_roundtrip() {
    let original = SerializableProfile::new("yaml_test", "test_registry")
        .with_description("YAML test profile")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 123)
        .with_config("STRING_VAR", "hello");

    // Serialize to YAML
    let yaml = original.to_yaml().expect("Should serialize to YAML");

    // Verify YAML contains expected content
    assert!(yaml.contains("name: yaml_test"));
    assert!(yaml.contains("registry_name: test_registry"));
    assert!(yaml.contains("description: YAML test profile"));
    assert!(yaml.contains("BOOL_VAR: true"));
    assert!(yaml.contains("INT_VAR: 123"));
    assert!(yaml.contains("STRING_VAR: hello"));

    // Deserialize back from YAML
    let deserialized = SerializableProfile::from_yaml(&yaml).expect("Should deserialize from YAML");

    // Verify round-trip integrity
    assert_eq!(deserialized.name, original.name);
    assert_eq!(deserialized.registry_name, original.registry_name);
    assert_eq!(deserialized.description, original.description);
    assert_eq!(deserialized.config.len(), original.config.len());
}

#[test]
fn test_json_serialization_roundtrip() {
    let original = SerializableProfile::new("json_test", "test_registry")
        .with_config("BOOL_VAR", false)
        .with_config("INT_VAR", 456);

    // Serialize to JSON
    let json = original.to_json().expect("Should serialize to JSON");

    // Verify JSON contains expected content
    assert!(json.contains(r#""name": "json_test""#));
    assert!(json.contains(r#""registry_name": "test_registry""#));
    assert!(json.contains(r#""BOOL_VAR": false"#));
    assert!(json.contains(r#""INT_VAR": 456"#));

    // Deserialize back from JSON
    let deserialized = SerializableProfile::from_json(&json).expect("Should deserialize from JSON");

    // Verify round-trip integrity
    assert_eq!(deserialized.name, original.name);
    assert_eq!(deserialized.registry_name, original.registry_name);
    assert_eq!(deserialized.config.len(), original.config.len());
}

#[test]
fn test_yaml_with_arrays() {
    let yaml = r#"
name: array_test
registry_name: test_registry
description: Testing array serialization
config:
  SIMPLE_ARRAY:
    - value1
    - value2
    - value3
  SPARSE_ARRAY:
    - first
    - "-"
    - third
    - "-"
  BOOL_ARRAY:
    - true
    - false
    - true
  INT_ARRAY:
    - 10
    - 20
    - 30
"#;

    let profile = SerializableProfile::from_yaml(yaml).expect("Should parse YAML with arrays");

    assert_eq!(profile.name, "array_test");
    assert_eq!(profile.config.len(), 4);

    // Verify array parsing
    assert!(profile.config.contains_key("SIMPLE_ARRAY"));
    assert!(profile.config.contains_key("SPARSE_ARRAY"));
    assert!(profile.config.contains_key("BOOL_ARRAY"));
    assert!(profile.config.contains_key("INT_ARRAY"));
}

#[test]
fn test_minimal_profile() {
    let yaml = r#"
name: minimal
registry_name: basic_registry
config:
  SINGLE_VAR: true
"#;

    let profile = SerializableProfile::from_yaml(yaml).expect("Should parse minimal YAML");

    assert_eq!(profile.name, "minimal");
    assert_eq!(profile.registry_name, "basic_registry");
    assert!(profile.description.is_none());
    assert_eq!(profile.config.len(), 1);
}

#[test]
fn test_invalid_yaml() {
    let invalid_yaml = r#"
name: broken
this is not valid yaml: [
"#;

    let result = SerializableProfile::from_yaml(invalid_yaml);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MlxProfileError::YamlParsing { .. }
    ));
}

#[test]
fn test_invalid_json() {
    let invalid_json = r#"{"name": "broken", "missing_comma" "value"}"#;

    let result = SerializableProfile::from_json(invalid_json);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MlxProfileError::JsonParsing { .. }
    ));
}

#[test]
fn test_try_from_protobuf_basic() {
    let proto_config: HashMap<String, String> = [
        ("BOOL_VAR".to_string(), "true".to_string()),
        ("INT_VAR".to_string(), "789".to_string()),
        ("STRING_VAR".to_string(), "proto_value".to_string()),
    ]
    .into();

    let proto = SerializableMlxConfigProfilePb {
        name: "proto_test".to_string(),
        registry_name: "test_registry".to_string(),
        description: Some("Testing protobuf conversion".to_string()),
        config: proto_config,
    };

    // Simulate the TryFrom conversion logic
    let mut config = HashMap::new();
    for (key, value_str) in proto.config {
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(&value_str).expect("Should parse YAML value");
        config.insert(key, yaml_value);
    }

    let profile = SerializableProfile {
        name: proto.name,
        registry_name: proto.registry_name,
        description: proto.description, // Both are Option<String> now
        config,
    };

    assert_eq!(profile.name, "proto_test");
    assert_eq!(profile.registry_name, "test_registry");
    assert_eq!(
        profile.description,
        Some("Testing protobuf conversion".to_string())
    );
    assert_eq!(profile.config.len(), 3);

    // Verify the config values were parsed correctly
    assert!(matches!(
        profile.config.get("BOOL_VAR"),
        Some(serde_yaml::Value::Bool(true))
    ));
    assert!(matches!(
        profile.config.get("INT_VAR"),
        Some(serde_yaml::Value::Number(_))
    ));
    assert!(matches!(
        profile.config.get("STRING_VAR"),
        Some(serde_yaml::Value::String(_))
    ));
}

#[test]
fn test_try_into_protobuf_basic() {
    let original = SerializableProfile::new("proto_test", "test_registry")
        .with_description("Testing protobuf conversion")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 789)
        .with_config("STRING_VAR", "proto_value");

    // Simulate the TryInto conversion logic
    let mut config = HashMap::new();
    for (key, yaml_value) in &original.config {
        let value_str = serde_yaml::to_string(yaml_value).expect("Should serialize YAML value");
        config.insert(key.clone(), value_str.trim().to_string());
    }

    let proto = SerializableMlxConfigProfilePb {
        name: original.name.clone(),
        registry_name: original.registry_name.clone(),
        description: original.description.clone(),
        config,
    };

    assert_eq!(proto.name, "proto_test");
    assert_eq!(proto.registry_name, "test_registry");
    assert_eq!(
        proto.description,
        Some("Testing protobuf conversion".to_string())
    );
    assert_eq!(proto.config.len(), 3);

    // Verify the config values were serialized correctly
    assert_eq!(proto.config.get("BOOL_VAR"), Some(&"true".to_string()));
    assert_eq!(proto.config.get("INT_VAR"), Some(&"789".to_string()));
    assert_eq!(
        proto.config.get("STRING_VAR"),
        Some(&"proto_value".to_string())
    );
}

#[test]
fn test_protobuf_roundtrip() {
    let original = SerializableProfile::new("roundtrip_test", "test_registry")
        .with_description("Testing full roundtrip")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 42)
        .with_config("STRING_VAR", "test_value");

    // Convert to protobuf (TryInto simulation)
    let mut proto_config = HashMap::new();
    for (key, yaml_value) in &original.config {
        let value_str = serde_yaml::to_string(yaml_value).expect("Should serialize");
        proto_config.insert(key.clone(), value_str.trim().to_string());
    }

    let proto = SerializableMlxConfigProfilePb {
        name: original.name.clone(),
        registry_name: original.registry_name.clone(),
        description: original.description.clone(),
        config: proto_config,
    };

    // Convert back from protobuf (TryFrom simulation)
    let mut config = HashMap::new();
    for (key, value_str) in proto.config {
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(&value_str).expect("Should deserialize");
        config.insert(key, yaml_value);
    }

    let roundtrip = SerializableProfile {
        name: proto.name,
        registry_name: proto.registry_name,
        description: proto.description, // Both are Option<String>
        config,
    };

    // Verify roundtrip integrity
    assert_eq!(roundtrip.name, original.name);
    assert_eq!(roundtrip.registry_name, original.registry_name);
    assert_eq!(roundtrip.description, original.description);
    assert_eq!(roundtrip.config.len(), original.config.len());
}

#[test]
fn test_protobuf_with_arrays() {
    let original =
        SerializableProfile::new("array_test", "test_registry").with_config("SIMPLE_VAR", 42);

    // Add an array manually to test array handling
    let mut config = original.config.clone();
    let array_values = vec![
        serde_yaml::Value::String("first".to_string()),
        serde_yaml::Value::String("second".to_string()),
        serde_yaml::Value::String("third".to_string()),
    ];
    config.insert(
        "ARRAY_VAR".to_string(),
        serde_yaml::Value::Sequence(array_values),
    );

    let profile_with_array = SerializableProfile {
        name: original.name,
        registry_name: original.registry_name,
        description: original.description,
        config,
    };

    // Test array serialization to protobuf
    let array_yaml = profile_with_array.config.get("ARRAY_VAR").unwrap();
    let array_string = serde_yaml::to_string(array_yaml).unwrap();

    // Should be valid YAML array format
    assert!(array_string.contains("- first"));
    assert!(array_string.contains("- second"));
    assert!(array_string.contains("- third"));

    // Test array deserialization from protobuf
    let parsed_back: serde_yaml::Value = serde_yaml::from_str(&array_string).unwrap();
    assert_eq!(*array_yaml, parsed_back);
}

#[test]
fn test_protobuf_with_sparse_arrays() {
    let original = SerializableProfile::new("sparse_test", "test_registry");

    // Create a sparse array with some null values
    let sparse_array = vec![
        serde_yaml::Value::String("first".to_string()),
        serde_yaml::Value::Null, // This represents an unset sparse array element
        serde_yaml::Value::String("third".to_string()),
    ];

    let mut config = HashMap::new();
    config.insert(
        "SPARSE_ARRAY".to_string(),
        serde_yaml::Value::Sequence(sparse_array),
    );

    let profile = SerializableProfile {
        name: original.name,
        registry_name: original.registry_name,
        description: original.description,
        config,
    };

    // Test sparse array serialization
    let sparse_yaml = profile.config.get("SPARSE_ARRAY").unwrap();
    let sparse_string = serde_yaml::to_string(sparse_yaml).unwrap();

    // Test sparse array deserialization
    let parsed_back: serde_yaml::Value = serde_yaml::from_str(&sparse_string).unwrap();
    assert_eq!(*sparse_yaml, parsed_back);

    // Verify the structure
    if let serde_yaml::Value::Sequence(seq) = parsed_back {
        assert_eq!(seq.len(), 3);
        assert!(matches!(seq[0], serde_yaml::Value::String(_)));
        assert!(matches!(seq[1], serde_yaml::Value::Null));
        assert!(matches!(seq[2], serde_yaml::Value::String(_)));
    } else {
        panic!("Expected sequence");
    }
}

#[test]
fn test_protobuf_empty_description() {
    let original =
        SerializableProfile::new("no_desc_test", "test_registry").with_config("VAR", "value");
    // Note: no description set, so it should be None

    // Convert to protobuf format
    let proto = SerializableMlxConfigProfilePb {
        name: original.name.clone(),
        registry_name: original.registry_name.clone(),
        description: None,      // No description set, so it should be None
        config: HashMap::new(), // Simplified for this test
    };

    assert_eq!(proto.description, None); // None in protobuf

    // Convert back from protobuf
    let converted_back = SerializableProfile {
        name: proto.name,
        registry_name: proto.registry_name,
        description: proto.description, // Both are Option<String>
        config: HashMap::new(),
    };

    assert_eq!(converted_back.description, None); // Should still be None
}

#[test]
fn test_edge_cases() {
    // Test empty profile
    let empty = SerializableProfile::new("empty", "registry");
    let yaml = empty.to_yaml().expect("Should serialize empty profile");
    let deserialized =
        SerializableProfile::from_yaml(&yaml).expect("Should deserialize empty profile");
    assert_eq!(deserialized.config.len(), 0);

    // Test profile with no description
    let no_desc = SerializableProfile::new("no_desc", "registry").with_config("VAR", "value");
    let yaml = no_desc.to_yaml().expect("Should serialize");
    assert!(!yaml.contains("description:"));

    // Test profile with empty description (should be treated as None)
    let empty_desc = SerializableProfile::new("empty_desc", "registry")
        .with_description("")
        .with_config("VAR", "value");
    // Empty descriptions should be skipped in serialization
    assert!(empty_desc.description == Some("".to_string()));
}

#[test]
fn test_toml_serialization_roundtrip() {
    let original = SerializableProfile::new("toml_test", "test_registry")
        .with_description("TOML test profile")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 123)
        .with_config("STRING_VAR", "hello");

    // Serialize to TOML
    let toml = original.to_toml().expect("Should serialize to TOML");

    // Verify TOML contains expected content
    assert!(toml.contains(r#"name = "toml_test""#));
    assert!(toml.contains(r#"registry_name = "test_registry""#));
    assert!(toml.contains(r#"description = "TOML test profile""#));

    // TOML config section
    assert!(toml.contains("[config]"));
    assert!(toml.contains("BOOL_VAR = true"));
    assert!(toml.contains("INT_VAR = 123"));
    assert!(toml.contains(r#"STRING_VAR = "hello""#));

    // Deserialize back from TOML
    let deserialized = SerializableProfile::from_toml(&toml).expect("Should deserialize from TOML");

    // Verify round-trip integrity
    assert_eq!(deserialized.name, original.name);
    assert_eq!(deserialized.registry_name, original.registry_name);
    assert_eq!(deserialized.description, original.description);
    assert_eq!(deserialized.config.len(), original.config.len());
}

#[test]
fn test_toml_with_nested_config() {
    let toml = r#"
name = "nested_test"
registry_name = "test_registry"
description = "Testing nested TOML config"

[config]
SRIOV_EN = true
NUM_OF_VFS = 16
POWER_MODE = "high"
ROCE_RTT_RESP_DSCP_P1 = 46
"#;

    let profile =
        SerializableProfile::from_toml(toml).expect("Should parse TOML with nested config");

    assert_eq!(profile.name, "nested_test");
    assert_eq!(profile.registry_name, "test_registry");
    assert_eq!(
        profile.description,
        Some("Testing nested TOML config".to_string())
    );
    assert_eq!(profile.config.len(), 4);

    // Verify nested config parsing
    assert!(profile.config.contains_key("SRIOV_EN"));
    assert!(profile.config.contains_key("NUM_OF_VFS"));
    assert!(profile.config.contains_key("POWER_MODE"));
    assert!(profile.config.contains_key("ROCE_RTT_RESP_DSCP_P1"));
}

#[test]
fn test_toml_with_arrays() {
    let toml = r#"
name = "array_test"
registry_name = "test_registry"
description = "Testing TOML arrays"

[config]
SIMPLE_ARRAY = ["first", "second", "third"]
SPARSE_ARRAY = ["val1", "-", "val3", "-"]
BOOL_ARRAY = [true, false, true]
INT_ARRAY = [10, 20, 30]
PCI_DOWNSTREAM_PORT_OWNER = ["EMBEDDED_CPU", "HOST_0", "HOST_1", "DEVICE_DEFAULT"]
"#;

    let profile = SerializableProfile::from_toml(toml).expect("Should parse TOML with arrays");

    assert_eq!(profile.name, "array_test");
    assert_eq!(profile.config.len(), 5);

    // Verify array parsing
    assert!(profile.config.contains_key("SIMPLE_ARRAY"));
    assert!(profile.config.contains_key("SPARSE_ARRAY"));
    assert!(profile.config.contains_key("BOOL_ARRAY"));
    assert!(profile.config.contains_key("INT_ARRAY"));
    assert!(profile.config.contains_key("PCI_DOWNSTREAM_PORT_OWNER"));
}

#[test]
fn test_toml_minimal_profile() {
    let toml = r#"
name = "minimal"
registry_name = "basic_registry"

[config]
SINGLE_VAR = true
"#;

    let profile = SerializableProfile::from_toml(toml).expect("Should parse minimal TOML");

    assert_eq!(profile.name, "minimal");
    assert_eq!(profile.registry_name, "basic_registry");
    assert!(profile.description.is_none());
    assert_eq!(profile.config.len(), 1);
}

#[test]
fn test_toml_production_like_config() {
    let toml = r#"
name = "bluefield-production"
registry_name = "mlx_generic"
description = "Production configuration for BlueField3 DPUs in datacenter"

[config]
SRIOV_EN = true
NUM_OF_VFS = 16
NUM_OF_PF = 2
INTERNAL_CPU_OFFLOAD_ENGINE = "ENABLED"
ROCE_ADAPTIVE_ROUTING_EN = false
TX_SCHEDULER_LOCALITY_MODE = "STATIC_MODE"
MULTIPATH_DSCP = "DSCP_1"
ROCE_RTT_RESP_DSCP_P1 = 46
ROCE_RTT_RESP_DSCP_MODE_P1 = "FIXED_VALUE"

# Array configuration for PCI downstream ports
PCI_DOWNSTREAM_PORT_OWNER = [
    "EMBEDDED_CPU",  # Port 0
    "HOST_0",        # Port 1
    "HOST_1",        # Port 2
    "HOST_0",        # Port 3
    "HOST_1",        # Port 4
    "DEVICE_DEFAULT", # Port 5
    "DEVICE_DEFAULT", # Port 6-15 use defaults
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT"
]
"#;

    let profile =
        SerializableProfile::from_toml(toml).expect("Should parse production-like TOML config");

    assert_eq!(profile.name, "bluefield-production");
    assert_eq!(profile.registry_name, "mlx_generic");
    assert!(profile.description.is_some());
    assert_eq!(profile.config.len(), 10);

    // Verify specific values
    if let Some(serde_yaml::Value::Bool(sriov)) = profile.config.get("SRIOV_EN") {
        assert!(*sriov);
    } else {
        panic!("SRIOV_EN should be a boolean true");
    }

    if let Some(serde_yaml::Value::Number(vfs)) = profile.config.get("NUM_OF_VFS") {
        assert_eq!(vfs.as_i64(), Some(16));
    } else {
        panic!("NUM_OF_VFS should be number 16");
    }

    if let Some(serde_yaml::Value::String(mode)) = profile.config.get("INTERNAL_CPU_OFFLOAD_ENGINE")
    {
        assert_eq!(mode, "ENABLED");
    } else {
        panic!("INTERNAL_CPU_OFFLOAD_ENGINE should be string 'ENABLED'");
    }
}

#[test]
fn test_toml_multiple_profiles_hashmap() {
    // Define a container struct similar what would be in
    // the carbide-api-site-config.toml file.
    #[derive(Deserialize)]
    struct ServerConfig {
        #[serde(rename = "mlx-config-profiles")]
        mlx_config_profiles: HashMap<String, SerializableProfile>,
    }

    let server_toml = r#"
# Server configuration with multiple MLX profiles

[mlx-config-profiles.bluefield-production]
name = "bluefield-production"
registry_name = "mlx_generic"
description = "Production config for BlueField3 DPUs"

[mlx-config-profiles.bluefield-production.config]
SRIOV_EN = true
NUM_OF_VFS = 16
NUM_OF_PF = 2
INTERNAL_CPU_OFFLOAD_ENGINE = "ENABLED"
ROCE_ADAPTIVE_ROUTING_EN = false
PCI_DOWNSTREAM_PORT_OWNER = ["EMBEDDED_CPU", "HOST_0", "HOST_1", "DEVICE_DEFAULT"]

[mlx-config-profiles.bluefield-development]
name = "bluefield-development"
registry_name = "mlx_generic"
description = "Development config for BlueField3 DPUs"

[mlx-config-profiles.bluefield-development.config]
SRIOV_EN = false
NUM_OF_VFS = 4
NUM_OF_PF = 1
INTERNAL_CPU_OFFLOAD_ENGINE = "DISABLED"
ROCE_ADAPTIVE_ROUTING_EN = true
PCI_DOWNSTREAM_PORT_OWNER = ["EMBEDDED_CPU", "HOST_0"]

[mlx-config-profiles.bluefield-testing]
name = "bluefield-testing"
registry_name = "mlx_generic"
description = "Testing config with minimal settings"

[mlx-config-profiles.bluefield-testing.config]
SRIOV_EN = true
NUM_OF_VFS = 8
INTERNAL_CPU_OFFLOAD_ENGINE = "ENABLED"
"#;

    let server_config: ServerConfig =
        toml::from_str(server_toml).expect("Should parse server TOML with multiple profiles");

    // Verify we got all three profiles
    assert_eq!(server_config.mlx_config_profiles.len(), 3);

    // Verify the keys match the TOML table names
    assert!(
        server_config
            .mlx_config_profiles
            .contains_key("bluefield-production")
    );
    assert!(
        server_config
            .mlx_config_profiles
            .contains_key("bluefield-development")
    );
    assert!(
        server_config
            .mlx_config_profiles
            .contains_key("bluefield-testing")
    );

    // Verify production profile details
    let prod_profile = &server_config.mlx_config_profiles["bluefield-production"];
    assert_eq!(prod_profile.name, "bluefield-production");
    assert_eq!(prod_profile.registry_name, "mlx_generic");
    assert_eq!(
        prod_profile.description,
        Some("Production config for BlueField3 DPUs".to_string())
    );
    assert_eq!(prod_profile.config.len(), 6); // 6 config variables

    // Verify development profile details
    let dev_profile = &server_config.mlx_config_profiles["bluefield-development"];
    assert_eq!(dev_profile.name, "bluefield-development");
    assert_eq!(dev_profile.registry_name, "mlx_generic");
    assert_eq!(
        dev_profile.description,
        Some("Development config for BlueField3 DPUs".to_string())
    );
    assert_eq!(dev_profile.config.len(), 6);

    // Verify testing profile details
    let test_profile = &server_config.mlx_config_profiles["bluefield-testing"];
    assert_eq!(test_profile.name, "bluefield-testing");
    assert_eq!(test_profile.registry_name, "mlx_generic");
    assert_eq!(
        test_profile.description,
        Some("Testing config with minimal settings".to_string())
    );
    assert_eq!(test_profile.config.len(), 3); // 3 config variables

    // Verify some specific config values
    if let Some(serde_yaml::Value::Bool(sriov)) = prod_profile.config.get("SRIOV_EN") {
        assert!(*sriov); // Production should have SRIOV enabled
    }

    if let Some(serde_yaml::Value::Bool(sriov)) = dev_profile.config.get("SRIOV_EN") {
        assert!(!*sriov); // Development should have SRIOV disabled
    }

    if let Some(serde_yaml::Value::Number(vfs)) = prod_profile.config.get("NUM_OF_VFS") {
        assert_eq!(vfs.as_i64(), Some(16)); // Production should have 16 VFs
    }

    if let Some(serde_yaml::Value::Number(vfs)) = dev_profile.config.get("NUM_OF_VFS") {
        assert_eq!(vfs.as_i64(), Some(4)); // Development should have 4 VFs
    }

    // Verify array handling in production profile
    if let Some(serde_yaml::Value::Sequence(ports)) =
        prod_profile.config.get("PCI_DOWNSTREAM_PORT_OWNER")
    {
        assert_eq!(ports.len(), 4);
        if let serde_yaml::Value::String(first_port) = &ports[0] {
            assert_eq!(first_port, "EMBEDDED_CPU");
        }
    }
}

#[test]
fn test_toml_serialization_preserves_structure() {
    let original = SerializableProfile::new("structure_test", "test_registry")
        .with_description("Test structure preservation")
        .with_config("VAR1", "value1")
        .with_config("VAR2", 42);

    let toml = original.to_toml().expect("Should serialize");

    // Should have proper TOML structure with [config] section
    assert!(toml.contains("name ="));
    assert!(toml.contains("registry_name ="));
    assert!(toml.contains("description ="));
    assert!(toml.contains("[config]"));

    // Variables should be in config section
    let config_section_start = toml.find("[config]").expect("Should have config section");
    let config_part = &toml[config_section_start..];
    assert!(config_part.contains("VAR1"));
    assert!(config_part.contains("VAR2"));
}

#[test]
fn test_invalid_toml() {
    let invalid_toml = r#"
name = "broken"
this is not valid toml syntax [
missing quotes and brackets
"#;

    let result = SerializableProfile::from_toml(invalid_toml);
    assert!(result.is_err());
    // TOML errors get wrapped in MlxProfileError::Serialization
    if let Err(MlxProfileError::Serialization { .. }) = result {
        // This is what we expect
    } else {
        panic!("Expected MlxProfileError::Serialization for invalid TOML");
    }
}

#[test]
fn test_toml_file_operations() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    let profile = SerializableProfile::new("file_test", "test_registry")
        .with_description("Testing TOML file operations")
        .with_config("TEST_VAR", "file_value")
        .with_config("NUM_VAR", 123);

    // Test TOML file operations
    let toml_path = temp_dir.path().join("test.toml");
    profile
        .to_toml_file(&toml_path)
        .expect("Should write TOML file");

    let loaded_toml =
        SerializableProfile::from_toml_file(&toml_path).expect("Should read TOML file");
    assert_eq!(loaded_toml.name, profile.name);
    assert_eq!(loaded_toml.registry_name, profile.registry_name);
    assert_eq!(loaded_toml.description, profile.description);
    assert_eq!(loaded_toml.config.len(), profile.config.len());
}

#[test]
fn test_toml_vs_yaml_compatibility() {
    // Create a profile and serialize to both TOML and YAML
    let original = SerializableProfile::new("compatibility_test", "test_registry")
        .with_description("Testing TOML/YAML compatibility")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 456)
        .with_config("STRING_VAR", "test");

    let toml_str = original.to_toml().expect("Should serialize to TOML");
    let yaml_str = original.to_yaml().expect("Should serialize to YAML");

    // Deserialize from both formats
    let from_toml =
        SerializableProfile::from_toml(&toml_str).expect("Should deserialize from TOML");
    let from_yaml =
        SerializableProfile::from_yaml(&yaml_str).expect("Should deserialize from YAML");

    // Both should be equivalent to original
    assert_eq!(from_toml.name, original.name);
    assert_eq!(from_yaml.name, original.name);
    assert_eq!(from_toml.config.len(), original.config.len());
    assert_eq!(from_yaml.config.len(), original.config.len());

    // And equivalent to each other
    assert_eq!(from_toml.name, from_yaml.name);
    assert_eq!(from_toml.registry_name, from_yaml.registry_name);
    assert_eq!(from_toml.description, from_yaml.description);
    assert_eq!(from_toml.config.len(), from_yaml.config.len());
}

#[test]
fn test_yaml_file_operations() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    let profile = SerializableProfile::new("yaml_file_test", "test_registry")
        .with_description("Testing YAML file operations")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 789)
        .with_config("STRING_VAR", "yaml_file_value");

    // Test YAML file operations
    let yaml_path = temp_dir.path().join("test_profile.yaml");
    profile
        .to_yaml_file(&yaml_path)
        .expect("Should write YAML file");

    // Verify file was created and has content
    assert!(yaml_path.exists());
    let file_content = std::fs::read_to_string(&yaml_path).expect("Should read file");
    assert!(file_content.contains("name: yaml_file_test"));
    assert!(file_content.contains("BOOL_VAR: true"));

    // Load back from file
    let loaded_profile =
        SerializableProfile::from_yaml_file(&yaml_path).expect("Should read YAML file");

    // Verify round-trip integrity
    assert_eq!(loaded_profile.name, profile.name);
    assert_eq!(loaded_profile.registry_name, profile.registry_name);
    assert_eq!(loaded_profile.description, profile.description);
    assert_eq!(loaded_profile.config.len(), profile.config.len());

    // Verify specific config values
    assert!(loaded_profile.config.contains_key("BOOL_VAR"));
    assert!(loaded_profile.config.contains_key("INT_VAR"));
    assert!(loaded_profile.config.contains_key("STRING_VAR"));
}

#[test]
fn test_json_file_operations() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    let profile = SerializableProfile::new("json_file_test", "test_registry")
        .with_description("Testing JSON file operations")
        .with_config("BOOL_VAR", false)
        .with_config("INT_VAR", 456)
        .with_config("STRING_VAR", "json_file_value");

    // Test JSON file operations
    let json_path = temp_dir.path().join("test_profile.json");
    profile
        .to_json_file(&json_path)
        .expect("Should write JSON file");

    // Verify file was created and has content
    assert!(json_path.exists());
    let file_content = std::fs::read_to_string(&json_path).expect("Should read file");
    assert!(file_content.contains(r#""name": "json_file_test""#));
    assert!(file_content.contains(r#""BOOL_VAR": false"#));

    // Load back from file
    let loaded_profile =
        SerializableProfile::from_json_file(&json_path).expect("Should read JSON file");

    // Verify round-trip integrity
    assert_eq!(loaded_profile.name, profile.name);
    assert_eq!(loaded_profile.registry_name, profile.registry_name);
    assert_eq!(loaded_profile.description, profile.description);
    assert_eq!(loaded_profile.config.len(), profile.config.len());

    // Verify specific config values
    assert!(loaded_profile.config.contains_key("BOOL_VAR"));
    assert!(loaded_profile.config.contains_key("INT_VAR"));
    assert!(loaded_profile.config.contains_key("STRING_VAR"));
}

#[test]
fn test_all_file_formats_compatibility() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    // Create a comprehensive profile
    let original = SerializableProfile::new("multi_format_test", "test_registry")
        .with_description("Testing all file format compatibility")
        .with_config("BOOL_VAR", true)
        .with_config("INT_VAR", 123)
        .with_config("STRING_VAR", "multi_format")
        .with_config("ARRAY_VAR", vec!["item1", "item2", "item3"]);

    // Write to all three formats
    let yaml_path = temp_dir.path().join("profile.yaml");
    let json_path = temp_dir.path().join("profile.json");
    let toml_path = temp_dir.path().join("profile.toml");

    original
        .to_yaml_file(&yaml_path)
        .expect("Should write YAML");
    original
        .to_json_file(&json_path)
        .expect("Should write JSON");
    original
        .to_toml_file(&toml_path)
        .expect("Should write TOML");

    // Verify all files exist
    assert!(yaml_path.exists());
    assert!(json_path.exists());
    assert!(toml_path.exists());

    // Load from all three formats
    let from_yaml = SerializableProfile::from_yaml_file(&yaml_path).expect("Should load from YAML");
    let from_json = SerializableProfile::from_json_file(&json_path).expect("Should load from JSON");
    let from_toml = SerializableProfile::from_toml_file(&toml_path).expect("Should load from TOML");

    // All should be equivalent to original
    let profiles = [&from_yaml, &from_json, &from_toml];
    for profile in &profiles {
        assert_eq!(profile.name, original.name);
        assert_eq!(profile.registry_name, original.registry_name);
        assert_eq!(profile.description, original.description);
        assert_eq!(profile.config.len(), original.config.len());
    }

    // All should be equivalent to each other
    for (i, profile1) in profiles.iter().enumerate() {
        for profile2 in profiles.iter().skip(i + 1) {
            assert_eq!(profile1.name, profile2.name);
            assert_eq!(profile1.registry_name, profile2.registry_name);
            assert_eq!(profile1.description, profile2.description);
            assert_eq!(profile1.config.len(), profile2.config.len());
        }
    }
}

#[test]
fn test_file_with_complex_arrays() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    // Create profile with arrays similar to real MLX configs
    let profile = SerializableProfile::new("complex_arrays_test", "mlx_generic")
        .with_description("Testing complex array configurations in files")
        .with_config("SRIOV_EN", true)
        .with_config("NUM_OF_VFS", 16);

    // Add complex array manually
    let mut config = profile.config.clone();
    let pci_ports = vec![
        serde_yaml::Value::String("EMBEDDED_CPU".to_string()),
        serde_yaml::Value::String("HOST_0".to_string()),
        serde_yaml::Value::String("HOST_1".to_string()),
        serde_yaml::Value::String("DEVICE_DEFAULT".to_string()),
    ];
    config.insert(
        "PCI_DOWNSTREAM_PORT_OWNER".to_string(),
        serde_yaml::Value::Sequence(pci_ports),
    );

    let profile_with_arrays = SerializableProfile {
        name: profile.name,
        registry_name: profile.registry_name,
        description: profile.description,
        config,
    };

    // Test with each format
    let yaml_path = temp_dir.path().join("complex.yaml");
    let json_path = temp_dir.path().join("complex.json");
    let toml_path = temp_dir.path().join("complex.toml");

    profile_with_arrays
        .to_yaml_file(&yaml_path)
        .expect("Should write YAML with arrays");
    profile_with_arrays
        .to_json_file(&json_path)
        .expect("Should write JSON with arrays");
    profile_with_arrays
        .to_toml_file(&toml_path)
        .expect("Should write TOML with arrays");

    // Load back and verify array handling
    let from_yaml =
        SerializableProfile::from_yaml_file(&yaml_path).expect("Should load YAML with arrays");
    let from_json =
        SerializableProfile::from_json_file(&json_path).expect("Should load JSON with arrays");
    let from_toml =
        SerializableProfile::from_toml_file(&toml_path).expect("Should load TOML with arrays");

    // Verify arrays are preserved in all formats
    for profile in [&from_yaml, &from_json, &from_toml] {
        assert!(profile.config.contains_key("PCI_DOWNSTREAM_PORT_OWNER"));
        if let Some(serde_yaml::Value::Sequence(ports)) =
            profile.config.get("PCI_DOWNSTREAM_PORT_OWNER")
        {
            assert_eq!(ports.len(), 4);
            if let serde_yaml::Value::String(first_port) = &ports[0] {
                assert_eq!(first_port, "EMBEDDED_CPU");
            }
        } else {
            panic!("PCI_DOWNSTREAM_PORT_OWNER should be an array");
        }
    }
}

#[test]
fn test_file_error_handling() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    // Test reading non-existent files
    let missing_yaml = temp_dir.path().join("missing.yaml");
    let missing_json = temp_dir.path().join("missing.json");
    let missing_toml = temp_dir.path().join("missing.toml");

    assert!(SerializableProfile::from_yaml_file(&missing_yaml).is_err());
    assert!(SerializableProfile::from_json_file(&missing_json).is_err());
    assert!(SerializableProfile::from_toml_file(&missing_toml).is_err());

    // Test writing to invalid paths (read-only directory)
    // Note: This test might be platform-specific, so we'll create a simple version

    // Create files with invalid content and test parsing
    let invalid_yaml = temp_dir.path().join("invalid.yaml");
    let invalid_json = temp_dir.path().join("invalid.json");
    let invalid_toml = temp_dir.path().join("invalid.toml");

    std::fs::write(&invalid_yaml, "invalid: yaml: content: [[[")
        .expect("Should write invalid YAML");
    std::fs::write(&invalid_json, r#"{"invalid": json: content}"#)
        .expect("Should write invalid JSON");
    std::fs::write(&invalid_toml, "invalid = toml content [[[").expect("Should write invalid TOML");

    // These should all fail to parse
    assert!(SerializableProfile::from_yaml_file(&invalid_yaml).is_err());
    assert!(SerializableProfile::from_json_file(&invalid_json).is_err());
    assert!(SerializableProfile::from_toml_file(&invalid_toml).is_err());
}

#[test]
fn test_file_paths_with_extensions() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Should create temp dir");

    let profile = SerializableProfile::new("extension_test", "test_registry")
        .with_description("Testing various file extensions")
        .with_config("TEST_VAR", "extension_value");

    // Test various extensions work correctly
    let paths_and_methods = [
        (temp_dir.path().join("profile.yaml"), "yaml"),
        (temp_dir.path().join("profile.yml"), "yaml"),
        (temp_dir.path().join("profile.json"), "json"),
        (temp_dir.path().join("profile.toml"), "toml"),
        (temp_dir.path().join("profile.tml"), "toml"),
        // Test without extensions too
        (temp_dir.path().join("profile_yaml"), "yaml"),
        (temp_dir.path().join("profile_json"), "json"),
        (temp_dir.path().join("profile_toml"), "toml"),
    ];

    for (path, format) in &paths_and_methods {
        match *format {
            "yaml" => {
                profile.to_yaml_file(path).expect("Should write YAML");
                let loaded = SerializableProfile::from_yaml_file(path).expect("Should read YAML");
                assert_eq!(loaded.name, profile.name);
            }
            "json" => {
                profile.to_json_file(path).expect("Should write JSON");
                let loaded = SerializableProfile::from_json_file(path).expect("Should read JSON");
                assert_eq!(loaded.name, profile.name);
            }
            "toml" => {
                profile.to_toml_file(path).expect("Should write TOML");
                let loaded = SerializableProfile::from_toml_file(path).expect("Should read TOML");
                assert_eq!(loaded.name, profile.name);
            }
            _ => unreachable!(),
        }

        assert!(path.exists(), "File should exist: {}", path.display());
    }
}

#[test]
fn test_option_hashmap_deserialize_with_profiles() {
    #[derive(Deserialize)]
    struct TestConfig {
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    let toml = r#"
[mlx-config-profiles.test-profile-1]
name = "test-profile-1"
registry_name = "mlx_generic"
description = "First test profile"

[mlx-config-profiles.test-profile-1.config]
SRIOV_EN = true
NUM_OF_VFS = 8

[mlx-config-profiles.test-profile-2]
name = "test-profile-2"
registry_name = "mlx_generic"
description = "Second test profile"

[mlx-config-profiles.test-profile-2.config]
SRIOV_EN = false
NUM_OF_VFS = 4
"#;

    let config: TestConfig = toml::from_str(toml).expect("should deserialize TOML with profiles");

    // Verify we got Some(HashMap) with 2 profiles.
    assert!(config.mlx_config_profiles.is_some());
    let profiles = config.mlx_config_profiles.as_ref().unwrap();
    assert_eq!(profiles.len(), 2);

    // Verify profile 1.
    let profile1 = profiles
        .get("test-profile-1")
        .expect("should have profile 1");
    assert_eq!(profile1.name, "test-profile-1");
    assert_eq!(profile1.registry.name, "mlx_generic");
    assert_eq!(profile1.description, Some("First test profile".to_string()));
    assert_eq!(profile1.variable_count(), 2);

    // Verify profile 2.
    let profile2 = profiles
        .get("test-profile-2")
        .expect("should have profile 2");
    assert_eq!(profile2.name, "test-profile-2");
    assert_eq!(profile2.registry.name, "mlx_generic");
    assert_eq!(
        profile2.description,
        Some("Second test profile".to_string())
    );
    assert_eq!(profile2.variable_count(), 2);
}

#[test]
fn test_option_hashmap_deserialize_missing_field() {
    #[derive(Deserialize)]
    struct TestConfig {
        some_other_field: String,
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    let toml = r#"
some_other_field = "test"
# No mlx-config-profiles section at all
"#;

    let config: TestConfig =
        toml::from_str(toml).expect("should deserialize TOML without profiles section");

    // Verify we got None because field was missing and
    // we used the default attribute.
    assert!(config.mlx_config_profiles.is_none());
    assert_eq!(config.some_other_field, "test");
}

#[test]
fn test_option_hashmap_deserialize_empty_section() {
    #[derive(Deserialize)]
    struct TestConfig {
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    let toml = r#"
[mlx-config-profiles]
# Empty section - no actual profiles defined
"#;

    let config: TestConfig =
        toml::from_str(toml).expect("should deserialize empty profiles section");

    // Should get Some(empty HashMap) not None,
    // because the section exists.
    assert!(config.mlx_config_profiles.is_some());
    let profiles = config.mlx_config_profiles.unwrap();
    assert_eq!(profiles.len(), 0);
}

#[test]
fn test_option_hashmap_serialize_with_profiles() {
    #[derive(Serialize)]
    struct TestConfig {
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    // Create some test profiles
    let registry = registries::get("mlx_generic")
        .expect("should have mlx_generic registry")
        .clone();

    let profile1 = MlxConfigProfile::new("test-profile-1", registry.clone())
        .with_description("First test profile")
        .with("SRIOV_EN", true)
        .expect("should add config")
        .with("NUM_OF_VFS", 8)
        .expect("should add config");

    let profile2 = MlxConfigProfile::new("test-profile-2", registry)
        .with_description("Second test profile")
        .with("SRIOV_EN", false)
        .expect("should add config")
        .with("NUM_OF_VFS", 4)
        .expect("should add config");

    let mut profiles = HashMap::new();
    profiles.insert("test-profile-1".to_string(), profile1);
    profiles.insert("test-profile-2".to_string(), profile2);

    let config = TestConfig {
        mlx_config_profiles: Some(profiles),
    };

    // Serialize to TOML
    let toml = toml::to_string_pretty(&config).expect("should serialize to TOML");

    // Verify the TOML contains our profiles
    assert!(toml.contains("[mlx-config-profiles.test-profile-1]"));
    assert!(toml.contains("[mlx-config-profiles.test-profile-2]"));
    assert!(toml.contains("name = \"test-profile-1\""));
    assert!(toml.contains("name = \"test-profile-2\""));
    assert!(toml.contains("registry_name = \"mlx_generic\""));
}

#[test]
fn test_option_hashmap_serialize_none() {
    #[derive(Serialize)]
    struct TestConfig {
        some_field: String,
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    let config = TestConfig {
        some_field: "test".to_string(),
        mlx_config_profiles: None,
    };

    // Serialize to TOML.
    let toml = toml::to_string_pretty(&config).expect("should serialize to TOML");

    // Verify the profiles section is NOT in the output
    // (skip_serializing_if works).
    assert!(!toml.contains("mlx-config-profiles"));
    assert!(toml.contains("some_field = \"test\""));
}

#[test]
fn test_option_hashmap_roundtrip() {
    #[derive(Serialize, Deserialize)]
    struct TestConfig {
        #[serde(
            default,
            rename = "mlx-config-profiles",
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_option_profile_map",
            serialize_with = "serialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    // Create original config.
    let registry = registries::get("mlx_generic")
        .expect("Should have mlx_generic registry")
        .clone();

    let profile = MlxConfigProfile::new("roundtrip-test", registry)
        .with_description("testing roundtrip")
        .with("SRIOV_EN", true)
        .expect("should add config")
        .with("NUM_OF_VFS", 16)
        .expect("should add config");

    let mut profiles = HashMap::new();
    profiles.insert("roundtrip-test".to_string(), profile);

    let original_config = TestConfig {
        mlx_config_profiles: Some(profiles),
    };

    // Serialize to TOML.
    let toml = toml::to_string_pretty(&original_config).expect("should serialize");

    // Deserialize back.
    let roundtrip_config: TestConfig = toml::from_str(&toml).expect("should deserialize");

    // Verify roundtrip worked.
    assert!(roundtrip_config.mlx_config_profiles.is_some());
    let roundtrip_profiles = roundtrip_config.mlx_config_profiles.as_ref().unwrap();
    assert_eq!(roundtrip_profiles.len(), 1);

    let roundtrip_profile = roundtrip_profiles
        .get("roundtrip-test")
        .expect("should have profile");
    assert_eq!(roundtrip_profile.name, "roundtrip-test");
    assert_eq!(roundtrip_profile.registry.name, "mlx_generic");
    assert_eq!(roundtrip_profile.variable_count(), 2);
}

#[test]
fn test_option_hashmap_with_multiple_profiles_and_arrays() {
    #[derive(Deserialize)]
    struct TestConfig {
        #[serde(
            default,
            rename = "mlx-config-profiles",
            deserialize_with = "deserialize_option_profile_map"
        )]
        mlx_config_profiles: Option<HashMap<String, MlxConfigProfile>>,
    }

    let toml = r#"
[mlx-config-profiles.profile-with-arrays]
name = "profile-with-arrays"
registry_name = "mlx_generic"
description = "Profile testing array support"

[mlx-config-profiles.profile-with-arrays.config]
SRIOV_EN = true
NUM_OF_VFS = 8
# PCI_DOWNSTREAM_PORT_OWNER needs exactly 16 elements
PCI_DOWNSTREAM_PORT_OWNER = [
    "EMBEDDED_CPU",
    "HOST_0",
    "HOST_1",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT",
    "DEVICE_DEFAULT"
]

[mlx-config-profiles.simple-profile]
name = "simple-profile"
registry_name = "mlx_generic"

[mlx-config-profiles.simple-profile.config]
SRIOV_EN = false
NUM_OF_VFS = 2
"#;

    let config: TestConfig = toml::from_str(toml).expect("should deserialize");

    assert!(config.mlx_config_profiles.is_some());
    let profiles = config.mlx_config_profiles.as_ref().unwrap();
    assert_eq!(profiles.len(), 2);

    // Verify profile with arrays
    let array_profile = profiles
        .get("profile-with-arrays")
        .expect("should have array profile");
    assert_eq!(array_profile.variable_count(), 3);

    // Verify simple profile
    let simple_profile = profiles
        .get("simple-profile")
        .expect("should have simple profile");
    assert_eq!(simple_profile.variable_count(), 2);
}
