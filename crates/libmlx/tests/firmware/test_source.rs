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

use libmlx::firmware::source::FirmwareSource;

// -- from_url: local paths --

#[test]
fn test_from_url_absolute_path() {
    let source = FirmwareSource::from_url("/opt/firmware/prod.signed.bin").unwrap();
    assert_eq!(source.description(), "local:/opt/firmware/prod.signed.bin");
}

#[test]
fn test_from_url_relative_path() {
    let source = FirmwareSource::from_url("firmware/prod.signed.bin").unwrap();
    assert_eq!(source.description(), "local:firmware/prod.signed.bin");
}

#[test]
fn test_from_url_file_prefix() {
    let source = FirmwareSource::from_url("file:///opt/firmware/prod.signed.bin").unwrap();
    assert_eq!(source.description(), "local:/opt/firmware/prod.signed.bin");
}

#[test]
fn test_from_url_file_prefix_relative() {
    let source = FirmwareSource::from_url("file://firmware/prod.signed.bin").unwrap();
    assert_eq!(source.description(), "local:firmware/prod.signed.bin");
}

// -- from_url: HTTP(S) --

#[test]
fn test_from_url_https() {
    let source =
        FirmwareSource::from_url("https://artifacts.example.com/fw/prod.signed.bin").unwrap();
    assert_eq!(
        source.description(),
        "http:https://artifacts.example.com/fw/prod.signed.bin"
    );
}

#[test]
fn test_from_url_http() {
    let source =
        FirmwareSource::from_url("http://internal.example.com/fw/prod.signed.bin").unwrap();
    assert_eq!(
        source.description(),
        "http:http://internal.example.com/fw/prod.signed.bin"
    );
}

// -- from_url: SSH (SCP-style) --

#[test]
fn test_from_url_ssh_with_user_and_path() {
    let source =
        FirmwareSource::from_url("ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin")
            .unwrap();
    assert_eq!(
        source.description(),
        "ssh://deploy@build-server.example.com:22:builds/fw/prod.signed.bin"
    );
}

#[test]
fn test_from_url_ssh_absolute_path() {
    let source =
        FirmwareSource::from_url("ssh://deploy@build-server.example.com:/opt/fw/prod.signed.bin")
            .unwrap();
    assert_eq!(
        source.description(),
        "ssh://deploy@build-server.example.com:22:/opt/fw/prod.signed.bin"
    );
}

#[test]
fn test_from_url_ssh_no_user() {
    let source =
        FirmwareSource::from_url("ssh://build-server.example.com:builds/fw/prod.signed.bin")
            .unwrap();
    // Username defaults to current user or "root".
    let desc = source.description();
    assert!(desc.contains("build-server.example.com:22:builds/fw/prod.signed.bin"));
}

#[test]
fn test_from_url_ssh_missing_path() {
    let result = FirmwareSource::from_url("ssh://deploy@build-server.example.com");
    assert!(result.is_err());
}

#[test]
fn test_from_url_ssh_empty_path() {
    let result = FirmwareSource::from_url("ssh://deploy@build-server.example.com:");
    assert!(result.is_err());
}

#[test]
fn test_from_url_ssh_missing_host() {
    let result = FirmwareSource::from_url("ssh://:path/to/file");
    assert!(result.is_err());
}

// -- direct constructors --

#[test]
fn test_local_constructor() {
    let source = FirmwareSource::local("/path/to/firmware.bin");
    assert_eq!(source.description(), "local:/path/to/firmware.bin");
}

#[test]
fn test_http_constructor() {
    let source = FirmwareSource::http("https://example.com/fw.bin");
    assert_eq!(source.description(), "http:https://example.com/fw.bin");
}

#[test]
fn test_ssh_constructor() {
    let source = FirmwareSource::ssh("build-server.example.com", "/builds/fw/prod.signed.bin");
    let desc = source.description();
    assert!(desc.contains("build-server.example.com"));
    assert!(desc.contains("/builds/fw/prod.signed.bin"));
}

#[test]
fn test_ssh_builder_methods() {
    let source = FirmwareSource::ssh("host.example.com", "/path/to/fw.bin")
        .with_username("deploy")
        .with_port(2222);
    assert_eq!(
        source.description(),
        "ssh://deploy@host.example.com:2222:/path/to/fw.bin"
    );
}
