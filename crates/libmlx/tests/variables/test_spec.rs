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
    assert!(matches!(spec, MlxVariableSpec::Boolean));
}
