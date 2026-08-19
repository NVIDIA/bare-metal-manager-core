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

//! Merges an operator-supplied supplemental NVUE config into the agent's
//! generated config before it is applied, so the supplemental content is part
//! of the same atomic NVUE revision rather than a second, racing write.
//!
//! The supplemental document is an RFC 7386 JSON Merge Patch over the `set`
//! section of the generated startup config: objects merge recursively, any
//! other value replaces the target, and `null` deletes a key. Merge-patch
//! suits NVUE because NVUE models collections as objects-keyed-by-name, not
//! arrays. The merged `set` section must still deserialize as
//! [`nvue_client::config::NvueConfig`], whose `deny_unknown_fields` rejects
//! patches that introduce NVUE sections the agent does not model.

use eyre::WrapErr;
use nvue_client::config::NvueConfigWithHeader;

/// Applies the JSON merge-patch in `patch_json` to the `set` section of the
/// YAML startup config in `nvue_yaml` and returns the merged YAML document.
/// The `header` entry is passed through untouched.
///
/// The whole merge stays in the `serde_yaml::Value` domain (JSON is a YAML
/// subset, so the patch parses with serde_yaml too). `serde_json::Value` must
/// not appear anywhere in this transformation: with the workspace-unified
/// `arbitrary_precision` feature, its numbers serialize into YAML as a
/// `{"$serde_json::private::Number": ...}` mapping, corrupting the config.
pub(crate) fn merge_into_nvue_yaml(nvue_yaml: &str, patch_json: &str) -> eyre::Result<String> {
    let patch: serde_yaml::Value = serde_yaml::from_str(patch_json)
        .wrap_err("supplemental network config is not valid JSON")?;
    if !patch.is_mapping() {
        return Err(eyre::eyre!(
            "supplemental network config must be a JSON object of NVUE config sections"
        ));
    }

    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(nvue_yaml).wrap_err("parsing generated NVUE config as YAML")?;
    let entries = doc
        .as_sequence_mut()
        .ok_or_else(|| eyre::eyre!("generated NVUE config is not a YAML sequence"))?;
    let set_key = serde_yaml::Value::from("set");
    let set_entry = entries
        .iter_mut()
        .find_map(|entry| entry.as_mapping_mut().and_then(|map| map.get_mut(&set_key)))
        .ok_or_else(|| eyre::eyre!("generated NVUE config has no 'set' entry"))?;

    yaml_merge_patch(set_entry, &patch);

    let merged = serde_yaml::to_string(&doc).wrap_err("serializing the merged NVUE config")?;

    // Reject unknown top-level NVUE sections (deny_unknown_fields) instead of
    // pushing a config NVUE may fail on as a whole-DPU apply. This is the same
    // parse the REST apply path performs on the final document.
    NvueConfigWithHeader::from_yaml(&merged)
        .wrap_err("merged NVUE config failed shape validation")?;

    Ok(merged)
}

/// RFC 7386 JSON Merge Patch: objects merge recursively, `null` deletes a key,
/// and any non-object patch value replaces the target wholesale.
fn yaml_merge_patch(target: &mut serde_yaml::Value, patch: &serde_yaml::Value) {
    let serde_yaml::Value::Mapping(patch_map) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_mapping() {
        *target = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let target_map = target
        .as_mapping_mut()
        .expect("target was just replaced with a mapping");
    for (key, patch_value) in patch_map {
        if patch_value.is_null() {
            target_map.remove(key);
        } else {
            yaml_merge_patch(
                target_map
                    .entry(key.clone())
                    .or_insert(serde_yaml::Value::Null),
                patch_value,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_NVUE_YAML: &str = r#"- header:
    model: BLUEFIELD
    nvue-api-version: nvue_v1
    rev-id: 1.0
    version: HBN 2.4.0
- set:
    interface:
      lo:
        ip:
          address:
            10.0.0.1/32: {}
        type: loopback
    vrf:
      default:
        router:
          bgp:
            autonomous-system: 65001
"#;

    #[test]
    fn merge_adds_new_vrf_and_interface() {
        let patch = r#"{
            "vrf": {"storage": {"router": {"bgp": {"autonomous-system": 65099}}}},
            "interface": {"pf0sf4": {"type": "swp"}}
        }"#;
        let merged = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&merged).unwrap();
        let set = &doc[1]["set"];
        // Existing content survives alongside the additions.
        assert_eq!(set["interface"]["lo"]["type"], "loopback");
        assert_eq!(set["interface"]["pf0sf4"]["type"], "swp");
        assert_eq!(
            set["vrf"]["default"]["router"]["bgp"]["autonomous-system"],
            65001
        );
        assert_eq!(
            set["vrf"]["storage"]["router"]["bgp"]["autonomous-system"],
            65099
        );
    }

    #[test]
    fn merge_overrides_nested_value() {
        let patch = r#"{"vrf": {"default": {"router": {"bgp": {"autonomous-system": 65002}}}}}"#;
        let merged = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&merged).unwrap();
        assert_eq!(
            doc[1]["set"]["vrf"]["default"]["router"]["bgp"]["autonomous-system"],
            65002
        );
    }

    #[test]
    fn merge_null_deletes_key() {
        let patch = r#"{"vrf": {"default": null}}"#;
        let merged = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&merged).unwrap();
        assert!(doc[1]["set"]["vrf"]["default"].is_null());
        // The sibling section is untouched.
        assert_eq!(doc[1]["set"]["interface"]["lo"]["type"], "loopback");
    }

    #[test]
    fn merge_preserves_header() {
        let patch = r#"{"vrf": {"storage": {}}}"#;
        let merged = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&merged).unwrap();
        assert_eq!(doc[0]["header"]["model"], "BLUEFIELD");
        assert_eq!(doc[0]["header"]["nvue-api-version"], "nvue_v1");
    }

    #[test]
    fn merged_result_still_parses_as_wire_config() {
        let patch = r#"{"vrf": {"storage": {}}}"#;
        let merged = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap();
        nvue_client::config::NvueConfigWithHeader::from_yaml(&merged)
            .expect("merged document must remain a valid NVUE startup config");
    }

    #[test]
    fn rejects_unknown_top_level_section() {
        let patch = r#"{"qos": {"egress": {}}}"#;
        let err = merge_into_nvue_yaml(BASE_NVUE_YAML, patch).unwrap_err();
        assert!(err.to_string().contains("shape validation"), "{err:#}");
    }

    #[test]
    fn rejects_non_object_patch() {
        let err = merge_into_nvue_yaml(BASE_NVUE_YAML, "[1, 2]").unwrap_err();
        assert!(err.to_string().contains("JSON object"), "{err:#}");
    }

    #[test]
    fn rejects_invalid_json() {
        let err = merge_into_nvue_yaml(BASE_NVUE_YAML, "{not json").unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "{err:#}");
    }
}
