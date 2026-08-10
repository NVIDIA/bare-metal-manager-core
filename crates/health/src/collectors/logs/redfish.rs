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

//! Shared mapping helpers for Redfish event and log-entry records.

use std::borrow::Cow;

use nv_redfish::schema::resource::Oem;

use crate::metrics::MetricLabel;

const NVIDIA_ERROR_ID_ATTR: &str = "oem.nvidia.error_id";
const REDFISH_EVENT_TYPE_ATTR: &str = "redfish.event.type";
const REDFISH_EVENT_SEVERITY_ATTR: &str = "redfish.event.severity";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RedfishLogType {
    Cper,
    Xid,
    RedfishEvent,
}

impl RedfishLogType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cper => "cper",
            Self::Xid => "xid",
            Self::RedfishEvent => "redfish_event",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RedfishLogFields<'a> {
    pub message: Option<&'a str>,
    pub message_args: Option<&'a [String]>,
    pub diagnostic_data_type: Option<&'a str>,
    pub has_cper: bool,
}

pub(super) fn redfish_log_type(fields: RedfishLogFields<'_>) -> RedfishLogType {
    if has_cper_evidence(fields) {
        return RedfishLogType::Cper;
    }

    if fields.message.is_some_and(contains_xid_token)
        || fields
            .message_args
            .unwrap_or_default()
            .iter()
            .any(|arg| contains_xid_token(arg))
    {
        return RedfishLogType::Xid;
    }

    RedfishLogType::RedfishEvent
}

pub(super) fn nvidia_error_id(oem: Option<&Oem>) -> Option<&str> {
    oem.and_then(|oem| {
        oem.additional_properties
            .pointer("/Nvidia/ErrorId")
            .and_then(serde_json::Value::as_str)
    })
}

pub(super) fn add_redfish_analyzer_attributes(
    attributes: &mut Vec<MetricLabel>,
    log_type: RedfishLogType,
    severity: Option<&str>,
    error_id: Option<&str>,
) {
    attributes.push((
        Cow::Borrowed(REDFISH_EVENT_TYPE_ATTR),
        log_type.as_str().to_string(),
    ));
    attributes.push((
        Cow::Borrowed(REDFISH_EVENT_SEVERITY_ATTR),
        normalize_redfish_severity(severity.unwrap_or_default()).to_string(),
    ));
    if let Some(error_id) = error_id {
        attributes.push((Cow::Borrowed(NVIDIA_ERROR_ID_ATTR), error_id.to_string()));
    }
}

pub(super) fn normalize_redfish_severity(s: &str) -> &'static str {
    if s.eq_ignore_ascii_case("Critical") {
        "Critical"
    } else if s.eq_ignore_ascii_case("Warning") {
        "Warning"
    } else if s.eq_ignore_ascii_case("OK") {
        "OK"
    } else {
        "Unknown"
    }
}

fn has_cper_evidence(fields: RedfishLogFields<'_>) -> bool {
    fields.has_cper
        || fields
            .diagnostic_data_type
            .is_some_and(is_cper_diagnostic_data_type)
}

fn is_cper_diagnostic_data_type(value: &str) -> bool {
    value.eq_ignore_ascii_case("CPER") || value.eq_ignore_ascii_case("CPERSection")
}

fn contains_xid_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3 {
        return false;
    }

    (0..=bytes.len() - 3).any(|index| {
        let before = index
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .copied();
        bytes[index..index + 3].eq_ignore_ascii_case(b"xid")
            && is_xid_boundary(before)
            && is_xid_boundary(bytes.get(index + 3).copied())
    })
}

fn is_xid_boundary(byte: Option<u8>) -> bool {
    byte.map(|byte| !byte.is_ascii_alphanumeric())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    struct TestFields {
        message: Option<&'static str>,
        message_args: &'static [&'static str],
        diagnostic_data_type: Option<&'static str>,
        has_cper: bool,
    }

    impl TestFields {
        fn basic(message: &'static str) -> Self {
            Self {
                message: Some(message),
                message_args: &[],
                diagnostic_data_type: None,
                has_cper: false,
            }
        }
    }

    fn with_fields<T>(input: TestFields, run: impl FnOnce(RedfishLogFields<'_>) -> T) -> T {
        let message_args: Vec<String> = input
            .message_args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect();
        run(RedfishLogFields {
            message: input.message,
            message_args: Some(&message_args),
            diagnostic_data_type: input.diagnostic_data_type,
            has_cper: input.has_cper,
        })
    }

    fn classify(input: TestFields) -> RedfishLogType {
        with_fields(input, redfish_log_type)
    }

    #[test]
    fn classifies_redfish_log_records() {
        check_values(
            [
                Check {
                    scenario: "bare platform event",
                    input: TestFields::basic("Fan 1 returned to OK"),
                    expect: RedfishLogType::RedfishEvent,
                },
                Check {
                    scenario: "xid in message",
                    input: TestFields::basic("GPU reported XID 94"),
                    expect: RedfishLogType::Xid,
                },
                Check {
                    scenario: "xid in message args",
                    input: TestFields {
                        message: Some("GPU fault"),
                        message_args: &["GPU0", "Xid 79"],
                        diagnostic_data_type: None,
                        has_cper: false,
                    },
                    expect: RedfishLogType::Xid,
                },
                Check {
                    scenario: "non-token xid substring",
                    input: TestFields::basic("oxidized connector warning"),
                    expect: RedfishLogType::RedfishEvent,
                },
                Check {
                    scenario: "cper diagnostic type",
                    input: TestFields {
                        message: Some("PCIe CPER event"),
                        message_args: &["XID 94"],
                        diagnostic_data_type: Some("CPER"),
                        has_cper: false,
                    },
                    expect: RedfishLogType::Cper,
                },
                Check {
                    scenario: "cper section diagnostic type",
                    input: TestFields {
                        message: Some("PCIe CPER section"),
                        message_args: &[],
                        diagnostic_data_type: Some("CPERSection"),
                        has_cper: false,
                    },
                    expect: RedfishLogType::Cper,
                },
                Check {
                    scenario: "cper object takes precedence over xid",
                    input: TestFields {
                        message: Some("GPU XID 94"),
                        message_args: &[],
                        diagnostic_data_type: None,
                        has_cper: true,
                    },
                    expect: RedfishLogType::Cper,
                },
            ],
            classify,
        );
    }

    #[test]
    fn analyzer_attributes_include_type_severity_and_error_id() {
        let mut attributes = Vec::new();

        add_redfish_analyzer_attributes(
            &mut attributes,
            RedfishLogType::RedfishEvent,
            None,
            Some("CPLD-PSEQ-FAULT"),
        );
        add_redfish_analyzer_attributes(
            &mut attributes,
            RedfishLogType::Xid,
            Some("warning"),
            None,
        );
        add_redfish_analyzer_attributes(
            &mut attributes,
            RedfishLogType::Cper,
            Some("CRITICAL"),
            None,
        );

        let attributes: Vec<(String, String)> = attributes
            .into_iter()
            .map(|(key, value)| (key.into_owned(), value))
            .collect();

        assert_eq!(
            attributes,
            [
                (
                    "redfish.event.type".to_string(),
                    "redfish_event".to_string()
                ),
                ("redfish.event.severity".to_string(), "Unknown".to_string()),
                (
                    "oem.nvidia.error_id".to_string(),
                    "CPLD-PSEQ-FAULT".to_string()
                ),
                ("redfish.event.type".to_string(), "xid".to_string()),
                ("redfish.event.severity".to_string(), "Warning".to_string()),
                ("redfish.event.type".to_string(), "cper".to_string()),
                ("redfish.event.severity".to_string(), "Critical".to_string()),
            ]
        );
    }

    #[test]
    fn extracts_nvidia_error_id_from_oem_data() {
        let oem: Oem = serde_json::from_value(serde_json::json!({
            "Nvidia": {"ErrorId": "CPLD-PSEQ-FAULT"}
        }))
        .expect("valid Redfish OEM object");

        assert_eq!(nvidia_error_id(Some(&oem)), Some("CPLD-PSEQ-FAULT"));
        assert_eq!(nvidia_error_id(None), None);
    }
}
