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

//! Packet-level counters for the DHCP server. The request and reply events
//! are metric-only (`log = off`): their rates are the INFO-level signal,
//! while the per-packet log lines stay reachable at DEBUG for forensics. A
//! drop is the operational error, so its event also writes the ERROR line --
//! one declaration moves the counter and logs the reason together.
//! Timestamp-file failures share a counter by operation while their paths,
//! host interface, and errors remain log-only diagnostics.

use carbide_instrument::{Event, LabelValue};
use dhcproto::v4::MessageType;

use crate::errors::DhcpError;

/// The DHCP message type of a packet, as a bounded metric label. The named
/// variants are the RFC 2131 message set this server handles; anything else
/// (lease-query extensions, unknown codes, a missing message-type option)
/// counts as `other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub enum MessageTypeLabel {
    Discover,
    Request,
    Offer,
    Ack,
    Nak,
    Release,
    Decline,
    Inform,
    Other,
}

impl From<MessageType> for MessageTypeLabel {
    fn from(message_type: MessageType) -> Self {
        match message_type {
            MessageType::Discover => Self::Discover,
            MessageType::Request => Self::Request,
            MessageType::Offer => Self::Offer,
            MessageType::Ack => Self::Ack,
            MessageType::Nak => Self::Nak,
            MessageType::Release => Self::Release,
            MessageType::Decline => Self::Decline,
            MessageType::Inform => Self::Inform,
            _ => Self::Other,
        }
    }
}

/// Why a packet was dropped, as a bounded metric label: one variant per
/// [`DhcpError`] variant, plus the drop sites that never construct a
/// `DhcpError` -- rate limiting, undersized packets, non-IPv4 sources, and
/// send failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub enum DropReason {
    RateLimited,
    TooShort,
    NotIpv4,
    SendFailed,
    IoError,
    ConfigParseFailure,
    MissingArgument,
    MissingOption,
    UnhandledMessageType,
    DhcpDeclineMessage,
    MissingRelayCode,
    InvalidInput,
    GenericError,
    UpstreamApiError,
    Utf8Error,
    PacketDecodeFailure,
    PacketEncodeFailure,
    AddressParseError,
    NonRelayedPacket,
    UnknownPacket,
    NotMyPacket,
    VendorClassParseError,
    MultipleInterfaces,
}

impl From<&DhcpError> for DropReason {
    fn from(error: &DhcpError) -> Self {
        match error {
            DhcpError::IoError(_) => Self::IoError,
            DhcpError::SerdeYaml(_) => Self::ConfigParseFailure,
            DhcpError::MissingArgument(_) => Self::MissingArgument,
            DhcpError::MissingOption(_) => Self::MissingOption,
            DhcpError::UnhandledMessageType(_) => Self::UnhandledMessageType,
            DhcpError::DhcpDeclineMessage(_, _) => Self::DhcpDeclineMessage,
            DhcpError::MissingRelayCode(_) => Self::MissingRelayCode,
            DhcpError::InvalidInput(_) => Self::InvalidInput,
            DhcpError::GenericError(_) => Self::GenericError,
            DhcpError::TonicStatusError(_) => Self::UpstreamApiError,
            DhcpError::Utf8Error(_) => Self::Utf8Error,
            DhcpError::PacketDecodeFailure(_) => Self::PacketDecodeFailure,
            DhcpError::PacketEncodeFailure(_) => Self::PacketEncodeFailure,
            DhcpError::AddressParseError(_) => Self::AddressParseError,
            DhcpError::NonRelayedPacket(_) => Self::NonRelayedPacket,
            DhcpError::UnknownPacket(_) => Self::UnknownPacket,
            DhcpError::NotMyPacket(_) => Self::NotMyPacket,
            DhcpError::VendorClassParseError(_) => Self::VendorClassParseError,
            DhcpError::MultipleInterfacesProvidedOneSupported(_) => Self::MultipleInterfaces,
        }
    }
}

/// The timestamp-file operation that failed. These are the only three file
/// operations performed by the DHCP server, so the metric remains bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum TimestampFileOperation {
    Initialize,
    Write,
    Read,
}

/// A DHCP packet was decoded from the wire, whatever becomes of it next.
#[derive(Event)]
#[event(
    event_name = "dhcp_server_request_received",
    metric_name = "carbide_dhcp_requests_total",
    component = "nico-dhcp",
    log = off,
    metric = counter,
    describe = "Number of DHCP packets received and decoded, by DHCP message type."
)]
pub struct DhcpRequestReceived {
    #[label]
    pub message_type: MessageTypeLabel,
}

/// A packet was dropped without a reply reaching the client -- anywhere from
/// the receive loop (rate limiting, undersized or non-IPv4 packets) through
/// packet processing to the final send.
#[derive(Event)]
#[event(
    event_name = "dhcp_server_packet_dropped",
    metric_name = "carbide_dhcp_dropped_requests_total",
    component = "nico-dhcp",
    message = "Dropped a DHCP packet",
    log = error,
    metric = counter,
    describe = "Number of DHCP packets dropped without a reply, by drop reason."
)]
pub struct DhcpPacketDropped {
    #[label]
    pub reason: DropReason,
    /// The detail behind the drop (an error's Display text where one exists).
    /// Log-line-only by construction; never a metric label.
    #[context]
    pub error: String,
}

/// A DHCP reply was sent, labelled by the reply's message type: an `offer` is
/// a proposed lease, an `ack` a committed one, a `nak` a refusal.
#[derive(Event)]
#[event(
    event_name = "dhcp_server_reply_sent",
    metric_name = "carbide_dhcp_replies_sent_total",
    component = "nico-dhcp",
    log = off,
    metric = counter,
    describe = "Number of DHCP replies sent, by reply message type."
)]
pub struct DhcpReplySent {
    #[label]
    pub message_type: MessageTypeLabel,
}

/// The startup write could not initialize the timestamp file. This server
/// generation does not start after the failure.
#[derive(Event)]
#[event(
    event_name = "dhcp_timestamp_file_initialization_failed",
    metric_name = "carbide_dhcp_timestamp_file_failures_total",
    component = "nico-dhcp",
    log = error,
    metric = counter,
    message = "Failed to init DHCP timestamps file",
    describe = "Number of DHCP timestamp file failures, by operation"
)]
pub(crate) struct DhcpTimestampFileInitializationFailed {
    #[label]
    operation: TimestampFileOperation,
    #[context]
    dhcp_timestamps_path: String,
    #[context]
    error: String,
}

impl DhcpTimestampFileInitializationFailed {
    pub(crate) fn new(dhcp_timestamps_path: String, error: String) -> Self {
        Self {
            operation: TimestampFileOperation::Initialize,
            dhcp_timestamps_path,
            error,
        }
    }
}

/// Updating the in-memory timestamp succeeded, but persisting the file failed.
/// Packet processing continues because the timestamp write is best effort.
#[derive(Event)]
#[event(
    event_name = "dhcp_timestamp_file_write_failed",
    metric_name = "carbide_dhcp_timestamp_file_failures_total",
    component = "nico-dhcp",
    log = error,
    metric = counter,
    message = "Failed to write DHCP timestamps file",
    describe = "Number of DHCP timestamp file failures, by operation"
)]
pub(crate) struct DhcpTimestampFileWriteFailed {
    #[label]
    operation: TimestampFileOperation,
    #[context]
    dhcp_timestamps_path: String,
    #[context]
    host_interface_id: String,
    #[context]
    error: String,
}

impl DhcpTimestampFileWriteFailed {
    pub(crate) fn new(
        dhcp_timestamps_path: String,
        host_interface_id: String,
        error: String,
    ) -> Self {
        Self {
            operation: TimestampFileOperation::Write,
            dhcp_timestamps_path,
            host_interface_id,
            error,
        }
    }
}

/// The control RPC could not read the timestamp file. It still returns an
/// empty list so callers keep treating an unreadable file as no requests yet.
#[derive(Event)]
#[event(
    event_name = "dhcp_timestamp_file_read_failed",
    metric_name = "carbide_dhcp_timestamp_file_failures_total",
    component = "nico-dhcp",
    log = warn,
    metric = counter,
    message = "Failed to read DHCP timestamps file",
    describe = "Number of DHCP timestamp file failures, by operation"
)]
pub(crate) struct DhcpTimestampFileReadFailed {
    #[label]
    operation: TimestampFileOperation,
    #[context]
    dhcp_timestamps_path: String,
    #[context]
    error: String,
}

impl DhcpTimestampFileReadFailed {
    pub(crate) fn new(dhcp_timestamps_path: String, error: String) -> Self {
        Self {
            operation: TimestampFileOperation::Read,
            dhcp_timestamps_path,
            error,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use dhcproto::v4::OptionCode;
    use dhcproto::v4::relay::RelayCode;

    use super::*;

    const TIMESTAMP_FILE_FAILURE_METRIC: &str = "carbide_dhcp_timestamp_file_failures_total";

    struct TimestampFileFailureInput {
        emit: fn(),
    }

    #[derive(Debug, PartialEq)]
    struct TimestampFileFailureObservation {
        initialize_delta: f64,
        write_delta: f64,
        read_delta: f64,
        log: TimestampFileFailureLog,
    }

    #[derive(Debug, PartialEq)]
    struct TimestampFileFailureLog {
        level: tracing::Level,
        metadata_name: String,
        message: String,
        event_name: Option<String>,
        metric_name: Option<String>,
        operation: Option<String>,
        dhcp_timestamps_path: Option<String>,
        host_interface_id: Option<String>,
        error: Option<String>,
    }

    fn emit_timestamp_initialization_failure() {
        emit(DhcpTimestampFileInitializationFailed::new(
            "/var/support/forge-dhcp/logs/dhcp_timestamps.json.tmp".to_string(),
            "permission denied".to_string(),
        ));
    }

    fn emit_timestamp_write_failure() {
        emit(DhcpTimestampFileWriteFailed::new(
            "/var/support/forge-dhcp/logs/dhcp_timestamps.json.tmp".to_string(),
            "60cef902-9779-4666-8362-c9bb4b37185f".to_string(),
            "read-only file system".to_string(),
        ));
    }

    fn emit_timestamp_read_failure() {
        emit(DhcpTimestampFileReadFailed::new(
            "/var/support/forge-dhcp/logs/dhcp_timestamps.json".to_string(),
            "file not found".to_string(),
        ));
    }

    fn observe_timestamp_file_failure(
        input: TimestampFileFailureInput,
    ) -> TimestampFileFailureObservation {
        let metrics = MetricsCapture::start();
        let mut logs = capture_logs(input.emit);
        assert_eq!(logs.len(), 1, "a timestamp-file failure logs once");
        let log = logs.pop().expect("the timestamp-file failure log");
        let field = |name: &str| log.field(name).map(str::to_owned);

        TimestampFileFailureObservation {
            initialize_delta: metrics.counter_delta(
                TIMESTAMP_FILE_FAILURE_METRIC,
                &[("operation", "initialize")],
            ),
            write_delta: metrics
                .counter_delta(TIMESTAMP_FILE_FAILURE_METRIC, &[("operation", "write")]),
            read_delta: metrics
                .counter_delta(TIMESTAMP_FILE_FAILURE_METRIC, &[("operation", "read")]),
            log: TimestampFileFailureLog {
                level: log.level,
                metadata_name: log.metadata_name.clone(),
                message: log.message.clone(),
                event_name: field("event_name"),
                metric_name: field("metric_name"),
                operation: field("operation"),
                dhcp_timestamps_path: field("dhcp_timestamps_path"),
                host_interface_id: field("host_interface_id"),
                error: field("error"),
            },
        }
    }

    fn expected_timestamp_file_failure(
        operation: &str,
        level: tracing::Level,
        event_name: &str,
        message: &str,
        dhcp_timestamps_path: &str,
        host_interface_id: Option<&str>,
        error: &str,
    ) -> TimestampFileFailureObservation {
        TimestampFileFailureObservation {
            initialize_delta: if operation == "initialize" { 1.0 } else { 0.0 },
            write_delta: if operation == "write" { 1.0 } else { 0.0 },
            read_delta: if operation == "read" { 1.0 } else { 0.0 },
            log: TimestampFileFailureLog {
                level,
                metadata_name: event_name.to_string(),
                message: message.to_string(),
                event_name: Some(event_name.to_string()),
                metric_name: Some(TIMESTAMP_FILE_FAILURE_METRIC.to_string()),
                operation: Some(operation.to_string()),
                dhcp_timestamps_path: Some(dhcp_timestamps_path.to_string()),
                host_interface_id: host_interface_id.map(str::to_owned),
                error: Some(error.to_string()),
            },
        }
    }

    /// Every timestamp-file failure keeps its historical diagnostic while the
    /// operation label selects exactly one series in the shared counter.
    #[test]
    fn timestamp_file_failures_log_and_count_by_operation() {
        // No other test in this binary triggers a timestamp-file failure. The
        // exact process-global counter deltas below rely on that isolation;
        // keep any future call-site failure test under the same log capture.
        check_values(
            [
                Check {
                    scenario: "initialization failure",
                    input: TimestampFileFailureInput {
                        emit: emit_timestamp_initialization_failure,
                    },
                    expect: expected_timestamp_file_failure(
                        "initialize",
                        tracing::Level::ERROR,
                        "dhcp_timestamp_file_initialization_failed",
                        "Failed to init DHCP timestamps file",
                        "/var/support/forge-dhcp/logs/dhcp_timestamps.json.tmp",
                        None,
                        "permission denied",
                    ),
                },
                Check {
                    scenario: "post-reply write failure",
                    input: TimestampFileFailureInput {
                        emit: emit_timestamp_write_failure,
                    },
                    expect: expected_timestamp_file_failure(
                        "write",
                        tracing::Level::ERROR,
                        "dhcp_timestamp_file_write_failed",
                        "Failed to write DHCP timestamps file",
                        "/var/support/forge-dhcp/logs/dhcp_timestamps.json.tmp",
                        Some("60cef902-9779-4666-8362-c9bb4b37185f"),
                        "read-only file system",
                    ),
                },
                Check {
                    scenario: "read failure",
                    input: TimestampFileFailureInput {
                        emit: emit_timestamp_read_failure,
                    },
                    expect: expected_timestamp_file_failure(
                        "read",
                        tracing::Level::WARN,
                        "dhcp_timestamp_file_read_failed",
                        "Failed to read DHCP timestamps file",
                        "/var/support/forge-dhcp/logs/dhcp_timestamps.json",
                        None,
                        "file not found",
                    ),
                },
            ],
            observe_timestamp_file_failure,
        );
    }

    #[test]
    fn message_type_label_maps_the_rfc2131_set_and_buckets_the_rest() {
        check_values(
            [
                Check {
                    scenario: "discover",
                    input: MessageType::Discover,
                    expect: MessageTypeLabel::Discover,
                },
                Check {
                    scenario: "request",
                    input: MessageType::Request,
                    expect: MessageTypeLabel::Request,
                },
                Check {
                    scenario: "offer",
                    input: MessageType::Offer,
                    expect: MessageTypeLabel::Offer,
                },
                Check {
                    scenario: "ack",
                    input: MessageType::Ack,
                    expect: MessageTypeLabel::Ack,
                },
                Check {
                    scenario: "nak",
                    input: MessageType::Nak,
                    expect: MessageTypeLabel::Nak,
                },
                Check {
                    scenario: "release",
                    input: MessageType::Release,
                    expect: MessageTypeLabel::Release,
                },
                Check {
                    scenario: "decline",
                    input: MessageType::Decline,
                    expect: MessageTypeLabel::Decline,
                },
                Check {
                    scenario: "inform",
                    input: MessageType::Inform,
                    expect: MessageTypeLabel::Inform,
                },
                Check {
                    scenario: "lease-query extension buckets as other",
                    input: MessageType::LeaseQuery,
                    expect: MessageTypeLabel::Other,
                },
                Check {
                    scenario: "unknown code buckets as other",
                    input: MessageType::Unknown(250),
                    expect: MessageTypeLabel::Other,
                },
            ],
            MessageTypeLabel::from,
        );
    }

    #[test]
    fn drop_reason_covers_every_dhcp_error_variant() {
        // 0x80 is a lone UTF-8 continuation byte -- the decode failure is the
        // point here.
        #[allow(invalid_from_utf8)]
        let utf8_error = std::str::from_utf8(&[0x80]).unwrap_err();

        check_values(
            [
                Check {
                    scenario: "io error",
                    input: DhcpError::IoError(std::io::Error::other("read failed")),
                    expect: DropReason::IoError,
                },
                Check {
                    scenario: "config parse failure",
                    input: DhcpError::SerdeYaml(serde_yaml::from_str::<usize>("[").unwrap_err()),
                    expect: DropReason::ConfigParseFailure,
                },
                Check {
                    scenario: "missing argument",
                    input: DhcpError::MissingArgument("interface".to_string()),
                    expect: DropReason::MissingArgument,
                },
                Check {
                    scenario: "missing option",
                    input: DhcpError::MissingOption(OptionCode::MessageType),
                    expect: DropReason::MissingOption,
                },
                Check {
                    scenario: "unhandled message type",
                    input: DhcpError::UnhandledMessageType(MessageType::Offer),
                    expect: DropReason::UnhandledMessageType,
                },
                Check {
                    scenario: "decline message",
                    input: DhcpError::DhcpDeclineMessage(
                        "10.0.0.1".to_string(),
                        "aa:bb:cc:dd:ee:ff".to_string(),
                    ),
                    expect: DropReason::DhcpDeclineMessage,
                },
                Check {
                    scenario: "missing relay code",
                    input: DhcpError::MissingRelayCode(RelayCode::LinkSelection),
                    expect: DropReason::MissingRelayCode,
                },
                Check {
                    scenario: "invalid input",
                    input: DhcpError::InvalidInput("bad".to_string()),
                    expect: DropReason::InvalidInput,
                },
                Check {
                    scenario: "generic error",
                    input: DhcpError::GenericError("oops".to_string()),
                    expect: DropReason::GenericError,
                },
                Check {
                    scenario: "gRPC failure names the upstream API",
                    input: DhcpError::TonicStatusError(tonic::Status::unavailable("api down")),
                    expect: DropReason::UpstreamApiError,
                },
                Check {
                    scenario: "utf8 error",
                    input: DhcpError::Utf8Error(utf8_error),
                    expect: DropReason::Utf8Error,
                },
                Check {
                    scenario: "packet decode failure",
                    input: DhcpError::PacketDecodeFailure(
                        dhcproto::error::DecodeError::NotEnoughBytes,
                    ),
                    expect: DropReason::PacketDecodeFailure,
                },
                Check {
                    scenario: "packet encode failure",
                    input: DhcpError::PacketEncodeFailure(
                        dhcproto::error::EncodeError::AddOverflow,
                    ),
                    expect: DropReason::PacketEncodeFailure,
                },
                Check {
                    scenario: "address parse error",
                    input: DhcpError::AddressParseError(
                        "not-an-ip".parse::<Ipv4Addr>().unwrap_err(),
                    ),
                    expect: DropReason::AddressParseError,
                },
                Check {
                    scenario: "non-relayed packet",
                    input: DhcpError::NonRelayedPacket(Ipv4Addr::new(0, 0, 0, 0)),
                    expect: DropReason::NonRelayedPacket,
                },
                Check {
                    scenario: "unknown packet",
                    input: DhcpError::UnknownPacket(2),
                    expect: DropReason::UnknownPacket,
                },
                Check {
                    scenario: "not my packet",
                    input: DhcpError::NotMyPacket("10.0.0.2".to_string()),
                    expect: DropReason::NotMyPacket,
                },
                Check {
                    scenario: "vendor class parse error",
                    input: DhcpError::VendorClassParseError("garbled".to_string()),
                    expect: DropReason::VendorClassParseError,
                },
                Check {
                    scenario: "multiple interfaces",
                    input: DhcpError::MultipleInterfacesProvidedOneSupported(2),
                    expect: DropReason::MultipleInterfaces,
                },
            ],
            |error| DropReason::from(&error),
        );
    }

    /// Every packet event moves exactly its counter, per label value. The
    /// request and grant counters are silent (the counters are the INFO-level
    /// signal, the packet logs stay DEBUG); a drop is the operational error,
    /// so its event also writes the error line -- one declaration, both
    /// signals.
    #[test]
    fn packet_events_count_per_label_and_drops_log_at_error() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            // Labels deliberately unused by any other test in this binary:
            // the capture mutex serializes only capture-holding tests, so
            // shared labels (a Discover request, an Offer grant) would race
            // with the end-to-end packet tests.
            emit(DhcpRequestReceived {
                message_type: MessageTypeLabel::Release,
            });
            emit(DhcpRequestReceived {
                message_type: MessageTypeLabel::Release,
            });
            emit(DhcpReplySent {
                message_type: MessageTypeLabel::Nak,
            });
            emit(DhcpPacketDropped {
                reason: DropReason::RateLimited,
                error: "parallel packet handling limit reached".to_string(),
            });
            let error = DhcpError::TonicStatusError(tonic::Status::unavailable("api down"));
            emit(DhcpPacketDropped {
                reason: DropReason::from(&error),
                error: error.to_string(),
            });
        });

        let (drop_logs, other_logs): (Vec<_>, Vec<_>) = logs
            .iter()
            .partition(|entry| entry.message.contains("Dropped a DHCP packet"));
        assert!(
            other_logs.is_empty(),
            "request/grant events are metric-only, got {other_logs:?}"
        );
        assert_eq!(drop_logs.len(), 2, "each drop writes one error line");
        assert!(
            drop_logs
                .iter()
                .all(|entry| entry.level == tracing::Level::ERROR)
        );
        let field = |entry: &&carbide_instrument::testing::CapturedLog, name: &str| {
            entry
                .fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            field(&drop_logs[0], "reason").as_deref(),
            Some("rate_limited")
        );
        assert!(
            field(&drop_logs[1], "error").is_some_and(|error| error.contains("api down")),
            "the drop line carries the upstream error detail"
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_dhcp_requests_total",
                &[("message_type", "release")]
            ),
            2.0
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_dhcp_replies_sent_total",
                &[("message_type", "nak")]
            ),
            1.0
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_dhcp_dropped_requests_total",
                &[("reason", "rate_limited")]
            ),
            1.0
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_dhcp_dropped_requests_total",
                &[("reason", "upstream_api_error")]
            ),
            1.0
        );
    }
}
