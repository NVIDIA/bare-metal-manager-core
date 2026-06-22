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

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use libmlx::firmware::source::FirmwareSource;

// from_url classifies a URL into a FirmwareSource whose `description()` records the
// scheme it picked. Local paths (bare or `file://`) become `local:`, HTTP(S) stays
// `http:<url>`, and an SCP-style `ssh://` URL renders host:port:path. A malformed
// ssh URL (no path, empty path, no host) is rejected. Each row maps the parsed
// source straight to its description, so one table folds every exact-description and
// every rejection case. (The no-user ssh case asserts a substring, so it stays
// standalone below.)
#[test]
fn from_url_classifies_by_scheme() {
    scenarios!(
        run = |url| {
            FirmwareSource::from_url(url)
                .map(|s| s.description())
                .map_err(drop)
        };
        "absolute local path" {
            "/opt/firmware/prod.signed.bin" => Yields("local:/opt/firmware/prod.signed.bin".to_string()),
        }

        "relative local path" {
            "firmware/prod.signed.bin" => Yields("local:firmware/prod.signed.bin".to_string()),
        }

        "file:// absolute path" {
            "file:///opt/firmware/prod.signed.bin" => Yields("local:/opt/firmware/prod.signed.bin".to_string()),
        }

        "file:// relative path" {
            "file://firmware/prod.signed.bin" => Yields("local:firmware/prod.signed.bin".to_string()),
        }

        "https URL" {
            "https://artifacts.example.com/fw/prod.signed.bin" => Yields("http:https://artifacts.example.com/fw/prod.signed.bin".to_string()),
        }

        "http URL" {
            "http://internal.example.com/fw/prod.signed.bin" => Yields("http:http://internal.example.com/fw/prod.signed.bin".to_string()),
        }

        "ssh with user and relative path" {
            "ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin" => Yields(
                "ssh://deploy@build-server.example.com:22:builds/fw/prod.signed.bin"
                    .to_string(),
            ),
        }

        "ssh with user and absolute path" {
            "ssh://deploy@build-server.example.com:/opt/fw/prod.signed.bin" => Yields(
                "ssh://deploy@build-server.example.com:22:/opt/fw/prod.signed.bin".to_string(),
            ),
        }

        "ssh missing path is rejected" {
            "ssh://deploy@build-server.example.com" => Fails,
        }

        "ssh empty path is rejected" {
            "ssh://deploy@build-server.example.com:" => Fails,
        }

        "ssh missing host is rejected" {
            "ssh://:path/to/file" => Fails,
        }
    );
}

// With no user in the ssh URL, the username defaults to the current user or "root",
// so we can only pin the host:port:path tail -- a substring assertion, not the exact
// equality the table above relies on.
#[test]
fn test_from_url_ssh_no_user() {
    let source =
        FirmwareSource::from_url("ssh://build-server.example.com:builds/fw/prod.signed.bin")
            .unwrap();
    let desc = source.description();
    assert!(desc.contains("build-server.example.com:22:builds/fw/prod.signed.bin"));
}

// -- direct constructors --

// The local() and http() constructors record their scheme in `description()` just as
// from_url does, but take a path/URL directly rather than classifying one.
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
