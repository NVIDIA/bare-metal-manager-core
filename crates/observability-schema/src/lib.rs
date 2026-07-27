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

//! Dependency-free vocabulary and validation shared by observability tooling.

use std::fmt;

mod fields;
pub use fields::*;

/// Field names owned by the Event log schema or formatter.
///
/// New code should query [`is_reserved_field`] for the surface it is
/// validating. This compatibility view contains the current
/// [`FieldSurface::InstrumentedEventLog`] set.
#[deprecated(note = "use RESERVED_FIELDS or is_reserved_field for a specific surface")]
pub const EVENT_LOG_RESERVED_FIELDS: &[&str] = &[
    "component",
    "event_name",
    "level",
    "location",
    "message",
    "metric_name",
    "msg",
    "span_id",
    "span_name",
];

/// The grammar required for stable event identities.
pub const EVENT_NAME_REQUIREMENT: &str = "event_name must be non-empty ASCII lower_snake_case, start with a letter, and contain no empty segments";

/// The error returned when an event identity does not follow the shared
/// [`EVENT_NAME_REQUIREMENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEventName;

impl fmt::Display for InvalidEventName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(EVENT_NAME_REQUIREMENT)
    }
}

impl std::error::Error for InvalidEventName {}

/// Validates a stable event identity.
///
/// Names contain lowercase ASCII letters, digits, and single underscores.
/// The first character must be a letter, and underscores may neither repeat
/// nor terminate the name.
pub fn validate_event_name(name: &str) -> Result<(), InvalidEventName> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(InvalidEventName);
    };
    if !first.is_ascii_lowercase() {
        return Err(InvalidEventName);
    }

    let mut previous_was_underscore = false;
    for byte in bytes {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_underscore = false,
            b'_' if !previous_was_underscore => previous_was_underscore = true,
            _ => return Err(InvalidEventName),
        }
    }

    if previous_was_underscore {
        return Err(InvalidEventName);
    }
    Ok(())
}

/// Returns whether `field_name` is owned by the Event log schema or formatter.
pub fn is_event_log_reserved_field(field_name: &str) -> bool {
    is_reserved_field(field_name, FieldSurface::InstrumentedEventLog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_name_grammar() {
        struct Case {
            scenario: &'static str,
            name: &'static str,
            expected: Result<(), InvalidEventName>,
        }

        for Case {
            scenario,
            name,
            expected,
        } in [
            Case {
                scenario: "single word",
                name: "connected",
                expected: Ok(()),
            },
            Case {
                scenario: "words and digits",
                name: "dhcp_v6_request_received",
                expected: Ok(()),
            },
            Case {
                scenario: "digits within a segment",
                name: "tls1_handshake_failed",
                expected: Ok(()),
            },
            Case {
                scenario: "empty",
                name: "",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "leading digit",
                name: "6_request_received",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "leading underscore",
                name: "_request_received",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "trailing underscore",
                name: "request_received_",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "empty segment",
                name: "request__received",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "uppercase",
                name: "RequestReceived",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "non-ASCII",
                name: "requést_received",
                expected: Err(InvalidEventName),
            },
            Case {
                scenario: "namespace punctuation",
                name: "dhcp.request_received",
                expected: Err(InvalidEventName),
            },
        ] {
            assert_eq!(validate_event_name(name), expected, "{scenario}: {name}");
        }
    }

    #[test]
    #[allow(deprecated)]
    fn event_log_reserved_fields_are_centralized() {
        let expected = RESERVED_FIELDS
            .iter()
            .filter(|field| is_reserved_field(field.name, FieldSurface::InstrumentedEventLog))
            .map(|field| field.name)
            .collect::<Vec<_>>();
        assert_eq!(EVENT_LOG_RESERVED_FIELDS, expected);

        for field in RESERVED_FIELDS {
            let expected = is_reserved_field(field.name, FieldSurface::InstrumentedEventLog);
            assert_eq!(
                is_event_log_reserved_field(field.name),
                expected,
                "{}",
                field.name
            );
        }
        assert!(!is_event_log_reserved_field("machine_id"));
    }
}
