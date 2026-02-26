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

use libmlx::firmware::config::FirmwareFlasherProfile;

#[test]
fn test_minimal_config() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "/opt/firmware/prod.signed.bin"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert_eq!(profile.firmware_spec.part_number, "900-9D3B4-00CV-TA0");
    assert_eq!(profile.firmware_spec.psid, "MT_0000000884");
    assert_eq!(profile.firmware_spec.version, "32.43.1014");
    assert_eq!(
        profile.flash_spec.firmware_url,
        "/opt/firmware/prod.signed.bin"
    );
    assert!(profile.flash_spec.firmware_credentials.is_none());
    assert!(profile.flash_spec.device_conf_url.is_none());
    assert!(profile.flash_spec.device_conf_credentials.is_none());
}

#[test]
fn test_config_with_version_and_options() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "/opt/firmware/prod.signed.bin"
reset = true
verify_image = true
verify_version = true
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert_eq!(profile.firmware_spec.version, "32.43.1014");
    assert!(profile.flash_options.reset);
    assert!(profile.flash_options.verify_image);
    assert!(profile.flash_options.verify_version);
    assert_eq!(profile.flash_options.reset_level, 3); // default
}

#[test]
fn test_config_with_bearer_token() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "https://artifacts.example.com/fw/prod.signed.bin"

[firmware_credentials]
type = "bearer_token"
token = "my-secret-token"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert!(profile.flash_spec.firmware_credentials.is_some());

    let source = profile.flash_spec.build_firmware_source().unwrap();
    assert!(source.description().contains("http:"));
}

#[test]
fn test_config_with_basic_auth() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "https://internal.example.com/fw/prod.signed.bin"

[firmware_credentials]
type = "basic_auth"
username = "deploy"
password = "s3cret"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert!(profile.flash_spec.firmware_credentials.is_some());
}

#[test]
fn test_config_with_ssh_key() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin"

[firmware_credentials]
type = "ssh_key"
path = "/home/deploy/.ssh/id_ed25519"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert!(profile.flash_spec.firmware_credentials.is_some());

    let source = profile.flash_spec.build_firmware_source().unwrap();
    assert!(source.description().contains("ssh://"));
}

#[test]
fn test_config_with_ssh_agent() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin"

[firmware_credentials]
type = "ssh_agent"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    assert!(profile.flash_spec.firmware_credentials.is_some());
}

#[test]
fn test_config_with_device_conf() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "https://artifacts.example.com/fw/debug.signed.bin"
device_conf_url = "ssh://deploy@build-server.example.com:builds/configs/debug.conf.bin"

[firmware_credentials]
type = "bearer_token"
token = "fw-token"

[device_conf_credentials]
type = "ssh_agent"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();

    assert_eq!(
        profile.flash_spec.device_conf_url.as_deref(),
        Some("ssh://deploy@build-server.example.com:builds/configs/debug.conf.bin")
    );
    assert!(profile.flash_spec.device_conf_credentials.is_some());

    let fw_source = profile.flash_spec.build_firmware_source().unwrap();
    assert!(fw_source.description().contains("http:"));

    let conf_source = profile.flash_spec.build_device_conf_source().unwrap();
    assert!(conf_source.is_some());
    assert!(conf_source.unwrap().description().contains("ssh://"));
}

#[test]
fn test_config_no_device_conf_returns_none() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
firmware_url = "/opt/firmware/prod.signed.bin"
"#;

    let profile = FirmwareFlasherProfile::from_toml(toml).unwrap();
    let conf_source = profile.flash_spec.build_device_conf_source().unwrap();
    assert!(conf_source.is_none());
}

#[test]
fn test_config_invalid_toml() {
    let toml = r#"
firmware_url = "missing closing quote
"#;

    let result = FirmwareFlasherProfile::from_toml(toml);
    assert!(result.is_err());
}

#[test]
fn test_config_missing_required_field() {
    let toml = r#"
part_number = "900-9D3B4-00CV-TA0"
psid = "MT_0000000884"
version = "32.43.1014"
"#;

    let result = FirmwareFlasherProfile::from_toml(toml);
    assert!(result.is_err());
}
