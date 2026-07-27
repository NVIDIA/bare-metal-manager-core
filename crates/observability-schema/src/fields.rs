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

//! Structured-field vocabulary shared by derives, source checks, and reports.
//!
//! This is deliberately an open registry. A missing definition means the key
//! is domain-specific, not invalid; grammar and the explicit reserved/alias
//! entries are the only rules that apply to unknown keys.

use std::borrow::Cow;
use std::fmt;

/// Where a structured field is declared or supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FieldSurface {
    /// A field written directly in a `tracing` event macro.
    PlainTracingEvent,
    /// A label or context field rendered by `carbide_instrument::Event`.
    InstrumentedEventLog,
    /// An attribute declared on a tracing span.
    Span,
    /// Metadata supplied by tracing, a subscriber, or a formatter.
    FormatterMetadata,
    /// A key attached to an OpenTelemetry metric.
    MetricLabel,
}

/// How a known key may be used on one surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldUse {
    /// The registry has no opinion about this key on this surface.
    Unspecified,
    /// The key is available to application code.
    Allowed,
    /// The key is available only when its values have a small, fixed domain.
    AllowedIfBounded,
    /// The framework supplies the key; application code must not shadow it.
    FrameworkOwned,
    /// Existing contracts may keep the key, but new uses should not add it.
    CompatibilityOnly,
    /// The key is not valid on this surface.
    Forbidden,
}

/// The shared meaning represented by one or more source keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FieldConcept {
    /// Human-readable log text.
    Message,
    /// Log severity.
    LogLevel,
    /// Source file and line.
    SourceLocation,
    /// Owning service or subsystem.
    Component,
    /// Correlation identity for a tracing span.
    SpanId,
    /// Stable identity for a typed Event.
    EventName,
    /// Prometheus family associated with a typed Event.
    MetricName,
    /// Static tracing span name.
    SpanName,
    /// A timestamp.
    Timestamp,
    /// An elapsed or active duration.
    Duration,
    /// A formatter or subscriber control.
    FormatterControl,
    /// An operational error.
    Error,
    /// A gRPC status code.
    GrpcStatusCode,
    /// An HTTP response status.
    HttpStatus,
    /// A domain explanation.
    Reason,
    /// An IP address.
    IpAddress,
    /// A MAC address.
    MacAddress,
    /// A socket, endpoint, or service address.
    NetworkAddress,
    /// A domain state.
    State,
    /// A count.
    Count,
    /// A measured quantity.
    Quantity,
    /// A command.
    Command,
    /// A protocol packet rendered for diagnostics.
    Packet,
    /// An object identifier.
    Identifier,
    /// An externally defined semantic-convention field.
    ExternalSemanticConvention,
}

/// The semantic value carried by a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SemanticType {
    /// Free-form text.
    Text,
    /// A boolean.
    Boolean,
    /// An integer.
    Integer,
    /// A numeric value that may be integral or fractional.
    Number,
    /// An error or error description.
    Error,
    /// An opaque identifier.
    Identifier,
    /// An IP address.
    IpAddress,
    /// A MAC address.
    MacAddress,
    /// A network address, optionally including a port.
    NetworkAddress,
    /// A protocol status code.
    StatusCode,
    /// A domain state.
    State,
    /// A timestamp.
    Timestamp,
    /// A duration.
    Duration,
    /// A command name or command line.
    Command,
}

/// The stable representation expected on the logging surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueFormat {
    /// Preserve the tracing value's native scalar type.
    Native,
    /// Render through `Display`.
    Display,
    /// Render through `Debug`.
    Debug,
    /// Render as ASCII `lower_snake_case`.
    LowerSnakeCase,
    /// Render as an uppercase log-level token.
    UppercaseToken,
    /// Preserve an opaque string representation.
    Opaque,
    /// Render as `file:line`.
    SourceLocation,
    /// Render as RFC 3339 text.
    Rfc3339,
    /// Render as a decimal number.
    Decimal,
}

/// Expected variation in a field's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cardinality {
    /// Values come from a small, fixed domain.
    Bounded,
    /// Values may grow with requests or managed objects.
    Unbounded,
    /// Boundedness depends on the value's source.
    SourceDependent,
}

/// Whether an alias can be normalized without inspecting its value or type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AliasConfidence {
    /// The alias has one meaning and may be enforced automatically.
    Unambiguous,
    /// The alias needs local type or domain context.
    ContextDependent,
}

/// A naming family used by role-qualified domain fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NamingFamily {
    /// Role-qualified identifiers such as `host_machine_id`.
    Identifier,
    /// IP addresses such as `bmc_ip_address`.
    IpAddress,
    /// MAC addresses such as `interface_mac_address`.
    MacAddress,
    /// Socket or service addresses such as `peer_address`.
    NetworkAddress,
    /// Entity states such as `machine_state`.
    State,
    /// Counts such as `pending_partition_count`.
    Count,
    /// Unit-suffixed quantities such as `retry_delay_seconds`.
    Quantity,
}

/// The normalization target for a known alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AliasTarget {
    /// An exact canonical field name.
    Field(&'static str),
    /// A role-qualified naming family.
    Family(NamingFamily),
}

/// One surface-specific rule for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SurfaceRule {
    /// The surface governed by this rule.
    pub surface: FieldSurface,
    /// How the field may be used there.
    pub usage: FieldUse,
}

/// The contract for one known structured-field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldDefinition {
    /// Shared semantic concept.
    pub concept: FieldConcept,
    /// Exact source key.
    pub name: &'static str,
    /// Semantic value type.
    pub semantic_type: SemanticType,
    /// Stable rendering convention.
    pub format: ValueFormat,
    /// Expected value cardinality.
    pub cardinality: Cardinality,
    /// Rules that vary by record surface.
    pub surface_rules: &'static [SurfaceRule],
    /// Concise operator-facing guidance.
    pub summary: &'static str,
}

impl FieldDefinition {
    /// Returns this field's rule for `surface`.
    pub fn use_on(&self, surface: FieldSurface) -> FieldUse {
        self.surface_rules
            .iter()
            .find(|rule| rule.surface == surface)
            .map_or(FieldUse::Unspecified, |rule| rule.usage)
    }
}

/// One discouraged spelling and its canonical target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldAlias {
    /// Discouraged source key.
    pub name: &'static str,
    /// Canonical exact field or naming family.
    pub target: AliasTarget,
    /// Surfaces on which this alias interpretation applies.
    pub surfaces: &'static [FieldSurface],
    /// Whether a source check can normalize the alias without type data.
    pub confidence: AliasConfidence,
    /// Concise reason for the mapping.
    pub summary: &'static str,
}

/// Shared guidance for one role-qualified naming family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamingFamilyDefinition {
    /// Stable family identity.
    pub family: NamingFamily,
    /// Representative canonical key.
    pub example: &'static str,
    /// Semantic value type.
    pub semantic_type: SemanticType,
    /// Stable rendering convention.
    pub format: ValueFormat,
    /// Expected value cardinality.
    pub cardinality: Cardinality,
    /// Rules that vary by record surface.
    pub surface_rules: &'static [SurfaceRule],
    /// Concise naming guidance.
    pub summary: &'static str,
}

/// The grammar used for structured fields outside metric labels.
pub const FIELD_NAME_REQUIREMENT: &str =
    "field names must be ASCII lower_snake_case or dot-separated lower_snake_case segments";

/// The error returned when a key does not follow its surface's grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidFieldName {
    surface: FieldSurface,
}

impl InvalidFieldName {
    /// Returns the surface whose grammar rejected the key.
    pub fn surface(self) -> FieldSurface {
        self.surface
    }
}

impl fmt::Display for InvalidFieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.surface {
            FieldSurface::MetricLabel => formatter.write_str(
                "metric label names start with an ASCII letter or underscore and contain only ASCII letters, digits, and underscores",
            ),
            _ => formatter.write_str(FIELD_NAME_REQUIREMENT),
        }
    }
}

impl std::error::Error for InvalidFieldName {}

const fn rule(surface: FieldSurface, usage: FieldUse) -> SurfaceRule {
    SurfaceRule { surface, usage }
}

const PLAIN: FieldSurface = FieldSurface::PlainTracingEvent;
const TYPED: FieldSurface = FieldSurface::InstrumentedEventLog;
const SPAN: FieldSurface = FieldSurface::Span;
const FORMATTER: FieldSurface = FieldSurface::FormatterMetadata;
const LABEL: FieldSurface = FieldSurface::MetricLabel;

/// Keys supplied by tracing, carbide-instrument, subscribers, or logfmt.
pub const RESERVED_FIELDS: &[FieldDefinition] = &[
    FieldDefinition {
        concept: FieldConcept::Component,
        name: "component",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Bounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Allowed),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::AllowedIfBounded),
        ],
        summary: "Set component on a span or subscriber, not on an event payload.",
    },
    FieldDefinition {
        concept: FieldConcept::EventName,
        name: "event_name",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::LowerSnakeCase,
        cardinality: Cardinality::Bounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::Forbidden),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Forbidden),
            rule(LABEL, FieldUse::CompatibilityOnly),
        ],
        summary: "carbide-instrument supplies the stable typed-Event identity.",
    },
    FieldDefinition {
        concept: FieldConcept::LogLevel,
        name: "level",
        semantic_type: SemanticType::Text,
        format: ValueFormat::UppercaseToken,
        cardinality: Cardinality::Bounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::AllowedIfBounded),
        ],
        summary: "The formatter supplies log severity.",
    },
    FieldDefinition {
        concept: FieldConcept::SourceLocation,
        name: "location",
        semantic_type: SemanticType::Text,
        format: ValueFormat::SourceLocation,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Forbidden),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::Forbidden),
        ],
        summary: "The formatter supplies the source file and line.",
    },
    FieldDefinition {
        concept: FieldConcept::Message,
        name: "message",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Forbidden),
            rule(LABEL, FieldUse::Forbidden),
        ],
        summary: "Tracing owns the event message field.",
    },
    FieldDefinition {
        concept: FieldConcept::MetricName,
        name: "metric_name",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Bounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::Forbidden),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Forbidden),
            rule(LABEL, FieldUse::CompatibilityOnly),
        ],
        summary: "carbide-instrument supplies the associated Prometheus family.",
    },
    FieldDefinition {
        concept: FieldConcept::Message,
        name: "msg",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Forbidden),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::Forbidden),
        ],
        summary: "logfmt renders tracing's message under msg.",
    },
    FieldDefinition {
        concept: FieldConcept::SpanId,
        name: "span_id",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::FrameworkOwned),
            rule(TYPED, FieldUse::FrameworkOwned),
            rule(SPAN, FieldUse::Allowed),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::Forbidden),
        ],
        summary: "Set span_id on the span; logfmt copies it to child event lines.",
    },
    FieldDefinition {
        concept: FieldConcept::SpanName,
        name: "span_name",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Bounded,
        surface_rules: &[
            rule(PLAIN, FieldUse::Forbidden),
            rule(TYPED, FieldUse::Forbidden),
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
            rule(LABEL, FieldUse::Forbidden),
        ],
        summary: "logfmt takes span_name from tracing metadata.",
    },
    FieldDefinition {
        concept: FieldConcept::Duration,
        name: "timing_busy_ns",
        semantic_type: SemanticType::Duration,
        format: ValueFormat::Decimal,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
        ],
        summary: "logfmt computes span busy time in nanoseconds.",
    },
    FieldDefinition {
        concept: FieldConcept::Duration,
        name: "timing_elapsed_us",
        semantic_type: SemanticType::Duration,
        format: ValueFormat::Decimal,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
        ],
        summary: "logfmt computes span elapsed time in microseconds.",
    },
    FieldDefinition {
        concept: FieldConcept::Timestamp,
        name: "timing_end_time",
        semantic_type: SemanticType::Timestamp,
        format: ValueFormat::Rfc3339,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
        ],
        summary: "logfmt optionally supplies the span end time.",
    },
    FieldDefinition {
        concept: FieldConcept::Duration,
        name: "timing_idle_ns",
        semantic_type: SemanticType::Duration,
        format: ValueFormat::Decimal,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
        ],
        summary: "logfmt computes span idle time in nanoseconds.",
    },
    FieldDefinition {
        concept: FieldConcept::Timestamp,
        name: "timing_start_time",
        semantic_type: SemanticType::Timestamp,
        format: ValueFormat::Rfc3339,
        cardinality: Cardinality::Unbounded,
        surface_rules: &[
            rule(SPAN, FieldUse::FrameworkOwned),
            rule(FORMATTER, FieldUse::FrameworkOwned),
        ],
        summary: "logfmt supplies the span start time.",
    },
];

const LOG_VALUES_NO_LABEL: &[SurfaceRule] = &[
    rule(PLAIN, FieldUse::Allowed),
    rule(TYPED, FieldUse::Allowed),
    rule(SPAN, FieldUse::Allowed),
    rule(LABEL, FieldUse::Forbidden),
];

const LOG_VALUES_BOUNDED_LABEL: &[SurfaceRule] = &[
    rule(PLAIN, FieldUse::Allowed),
    rule(TYPED, FieldUse::Allowed),
    rule(SPAN, FieldUse::Allowed),
    rule(LABEL, FieldUse::AllowedIfBounded),
];

const SPAN_ONLY: &[SurfaceRule] = &[
    rule(SPAN, FieldUse::Allowed),
    rule(LABEL, FieldUse::Forbidden),
];

const PLAIN_ONLY: &[SurfaceRule] = &[
    rule(PLAIN, FieldUse::Allowed),
    rule(LABEL, FieldUse::Forbidden),
];

/// Canonical common fields and established external semantic-convention keys.
pub const COMMON_FIELDS: &[FieldDefinition] = &[
    FieldDefinition {
        concept: FieldConcept::FormatterControl,
        name: "carbide.trace_root",
        semantic_type: SemanticType::Boolean,
        format: ValueFormat::Native,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "Marks a local span as an exported trace root.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "client.address",
        semantic_type: SemanticType::NetworkAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry client address.",
    },
    FieldDefinition {
        concept: FieldConcept::Count,
        name: "client.num_certs",
        semantic_type: SemanticType::Integer,
        format: ValueFormat::Native,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Number of client certificates presented with an API request.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "client.port",
        semantic_type: SemanticType::Integer,
        format: ValueFormat::Native,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry client port.",
    },
    FieldDefinition {
        concept: FieldConcept::Command,
        name: "command",
        semantic_type: SemanticType::Command,
        format: ValueFormat::Display,
        cardinality: Cardinality::SourceDependent,
        surface_rules: LOG_VALUES_BOUNDED_LABEL,
        summary: "Use the full word command instead of cmd; metric values must use a bounded command type.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "db.statement",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: LOG_VALUES_NO_LABEL,
        summary: "OpenTelemetry database statement text.",
    },
    FieldDefinition {
        concept: FieldConcept::Error,
        name: "error",
        semantic_type: SemanticType::Error,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: LOG_VALUES_NO_LABEL,
        summary: "Normalize incidental bindings such as e and err to error.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "forge.machine_id",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Forge tracing attribute for a machine identity.",
    },
    FieldDefinition {
        concept: FieldConcept::GrpcStatusCode,
        name: "grpc_status_code",
        semantic_type: SemanticType::StatusCode,
        format: ValueFormat::Display,
        cardinality: Cardinality::Bounded,
        surface_rules: LOG_VALUES_BOUNDED_LABEL,
        summary: "Use the explicit transport namespace for a gRPC status code.",
    },
    FieldDefinition {
        concept: FieldConcept::HttpStatus,
        name: "http.response.status_code",
        semantic_type: SemanticType::StatusCode,
        format: ValueFormat::Native,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry HTTP response status code.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "http.url",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry HTTP URL.",
    },
    FieldDefinition {
        concept: FieldConcept::HttpStatus,
        name: "http_status",
        semantic_type: SemanticType::StatusCode,
        format: ValueFormat::Display,
        cardinality: Cardinality::Bounded,
        surface_rules: LOG_VALUES_BOUNDED_LABEL,
        summary: "Use for the complete HTTP status or its numeric code.",
    },
    FieldDefinition {
        concept: FieldConcept::IpAddress,
        name: "ip_address",
        semantic_type: SemanticType::IpAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: LOG_VALUES_NO_LABEL,
        summary: "Add a semantic role when one is known.",
    },
    FieldDefinition {
        concept: FieldConcept::FormatterControl,
        name: "logfmt.suppress",
        semantic_type: SemanticType::Boolean,
        format: ValueFormat::Native,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "Suppresses the level=SPAN line when set to true.",
    },
    FieldDefinition {
        concept: FieldConcept::MacAddress,
        name: "mac_address",
        semantic_type: SemanticType::MacAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: LOG_VALUES_NO_LABEL,
        summary: "Add a semantic role when one is known.",
    },
    FieldDefinition {
        concept: FieldConcept::Error,
        name: "nico.error",
        semantic_type: SemanticType::Error,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "NICo request error text reserved on the API request span.",
    },
    FieldDefinition {
        concept: FieldConcept::Identifier,
        name: "nico.error_code",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::SourceDependent,
        surface_rules: SPAN_ONLY,
        summary: "Stable operator-facing NICo error code.",
    },
    FieldDefinition {
        concept: FieldConcept::SourceLocation,
        name: "nico.error_location",
        semantic_type: SemanticType::Text,
        format: ValueFormat::SourceLocation,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Source location where a NICo error became a transport status.",
    },
    FieldDefinition {
        concept: FieldConcept::Error,
        name: "nico.mitigation",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Operator action associated with a NICo error.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "otel.status_code",
        semantic_type: SemanticType::StatusCode,
        format: ValueFormat::LowerSnakeCase,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry span status.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "otel.status_message",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry span status description.",
    },
    FieldDefinition {
        concept: FieldConcept::Packet,
        name: "packet.received",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: PLAIN_ONLY,
        summary: "Decoded inbound DHCP packet rendered for debug logging.",
    },
    FieldDefinition {
        concept: FieldConcept::Packet,
        name: "packet.send",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: PLAIN_ONLY,
        summary: "Outbound DHCP packet rendered for debug logging.",
    },
    FieldDefinition {
        concept: FieldConcept::Reason,
        name: "reason",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::SourceDependent,
        surface_rules: LOG_VALUES_BOUNDED_LABEL,
        summary: "Use for a domain explanation that is not a Rust error.",
    },
    FieldDefinition {
        concept: FieldConcept::GrpcStatusCode,
        name: "rpc.grpc.status_code",
        semantic_type: SemanticType::StatusCode,
        format: ValueFormat::Native,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry gRPC status code.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "rpc.grpc.status_description",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry gRPC status description.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "rpc.method",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry RPC method.",
    },
    FieldDefinition {
        concept: FieldConcept::ExternalSemanticConvention,
        name: "rpc.service",
        semantic_type: SemanticType::Text,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Bounded,
        surface_rules: SPAN_ONLY,
        summary: "OpenTelemetry RPC service.",
    },
    FieldDefinition {
        concept: FieldConcept::Identifier,
        name: "tenant.organization_id",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Tenant organization identity attached to an API request span.",
    },
    FieldDefinition {
        concept: FieldConcept::Identifier,
        name: "user.id",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Opaque,
        cardinality: Cardinality::Unbounded,
        surface_rules: SPAN_ONLY,
        summary: "Authenticated user identity following OpenTelemetry conventions.",
    },
];

const LOG_SURFACES: &[FieldSurface] = &[PLAIN, TYPED, SPAN];
const EVENT_LOG_SURFACES: &[FieldSurface] = &[PLAIN, TYPED];

/// Known aliases. Metric-label spellings are excluded because those keys are
/// compatibility contracts rather than log-field cleanup candidates.
pub const FIELD_ALIASES: &[FieldAlias] = &[
    FieldAlias {
        name: "addr",
        target: AliasTarget::Family(NamingFamily::NetworkAddress),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use a role-specific address name.",
    },
    FieldAlias {
        name: "cmd",
        target: AliasTarget::Field("command"),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use the full word command.",
    },
    FieldAlias {
        name: "code",
        target: AliasTarget::Field("grpc_status_code"),
        surfaces: EVENT_LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name the protocol whose status code is being recorded.",
    },
    FieldAlias {
        name: "count",
        target: AliasTarget::Family(NamingFamily::Count),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name what is counted.",
    },
    FieldAlias {
        name: "e",
        target: AliasTarget::Field("error"),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use error when this binding holds a Rust error.",
    },
    FieldAlias {
        name: "err",
        target: AliasTarget::Field("error"),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::Unambiguous,
        summary: "Use the canonical error field.",
    },
    FieldAlias {
        name: "grpc_code",
        target: AliasTarget::Field("grpc_status_code"),
        surfaces: EVENT_LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use the canonical gRPC status field.",
    },
    FieldAlias {
        name: "http_status_code",
        target: AliasTarget::Field("http_status"),
        surfaces: EVENT_LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use the canonical HTTP status field.",
    },
    FieldAlias {
        name: "id",
        target: AliasTarget::Family(NamingFamily::Identifier),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name the concrete identifier type.",
    },
    FieldAlias {
        name: "ip",
        target: AliasTarget::Field("ip_address"),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use ip_address with a semantic role when known.",
    },
    FieldAlias {
        name: "mac",
        target: AliasTarget::Field("mac_address"),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Use mac_address with a semantic role when known.",
    },
    FieldAlias {
        name: "state",
        target: AliasTarget::Family(NamingFamily::State),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name the entity whose state is recorded.",
    },
    FieldAlias {
        name: "status_code",
        target: AliasTarget::Field("http_status"),
        surfaces: EVENT_LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name the protocol whose status is recorded.",
    },
    FieldAlias {
        name: "total",
        target: AliasTarget::Family(NamingFamily::Count),
        surfaces: LOG_SURFACES,
        confidence: AliasConfidence::ContextDependent,
        summary: "Name what is counted.",
    },
];

const FAMILY_LOG_ONLY: &[SurfaceRule] = &[
    rule(PLAIN, FieldUse::Allowed),
    rule(TYPED, FieldUse::Allowed),
    rule(SPAN, FieldUse::Allowed),
    rule(LABEL, FieldUse::Forbidden),
];

/// Open naming families for precise domain-specific fields.
pub const NAMING_FAMILIES: &[NamingFamilyDefinition] = &[
    NamingFamilyDefinition {
        family: NamingFamily::Count,
        example: "pending_partition_count",
        semantic_type: SemanticType::Integer,
        format: ValueFormat::Native,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Use <thing>_count and name what is counted.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::Identifier,
        example: "machine_id",
        semantic_type: SemanticType::Identifier,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Derive the default key from the concrete identifier type.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::IpAddress,
        example: "bmc_ip_address",
        semantic_type: SemanticType::IpAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Use *_ip_address for an IP without a port.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::MacAddress,
        example: "interface_mac_address",
        semantic_type: SemanticType::MacAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Use *_mac_address and add the semantic role when known.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::NetworkAddress,
        example: "peer_address",
        semantic_type: SemanticType::NetworkAddress,
        format: ValueFormat::Display,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Use a role-specific *_address name for sockets and endpoints.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::Quantity,
        example: "retry_delay_seconds",
        semantic_type: SemanticType::Number,
        format: ValueFormat::Native,
        cardinality: Cardinality::Unbounded,
        surface_rules: FAMILY_LOG_ONLY,
        summary: "Encode the unit in the key when the type does not.",
    },
    NamingFamilyDefinition {
        family: NamingFamily::State,
        example: "machine_state",
        semantic_type: SemanticType::State,
        format: ValueFormat::Display,
        cardinality: Cardinality::SourceDependent,
        surface_rules: LOG_VALUES_BOUNDED_LABEL,
        summary: "Name the entity, or use previous_state, next_state, or target_state.",
    },
];

fn is_lower_snake_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }

    let mut previous_was_underscore = false;
    for byte in bytes {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_underscore = false,
            b'_' if !previous_was_underscore => previous_was_underscore = true,
            _ => return false,
        }
    }
    !previous_was_underscore
}

/// Validates a key using the grammar of its source surface.
///
/// Tracing events and spans accept dot-separated semantic-convention names.
/// Metric labels retain the OpenTelemetry-compatible ASCII identifier grammar
/// already enforced by the Event derive.
pub fn validate_field_name(name: &str, surface: FieldSurface) -> Result<(), InvalidFieldName> {
    let valid = if surface == FieldSurface::MetricLabel {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    } else {
        name.split('.').all(is_lower_snake_segment)
    };

    if valid {
        Ok(())
    } else {
        Err(InvalidFieldName { surface })
    }
}

fn definition_by_name(name: &str) -> Option<&'static FieldDefinition> {
    RESERVED_FIELDS
        .iter()
        .chain(COMMON_FIELDS)
        .find(|definition| definition.name == name)
}

/// Returns a known field definition when it has policy for `surface`.
pub fn field_definition(name: &str, surface: FieldSurface) -> Option<&'static FieldDefinition> {
    definition_by_name(name)
        .filter(|definition| definition.use_on(surface) != FieldUse::Unspecified)
}

/// Returns the known policy for `name` on `surface`.
///
/// Unknown fields and known fields without a rule for this surface are
/// [`FieldUse::Unspecified`].
pub fn field_use(name: &str, surface: FieldSurface) -> FieldUse {
    field_definition(name, surface).map_or(FieldUse::Unspecified, |definition| {
        definition.use_on(surface)
    })
}

/// Returns whether application code must not declare `name` on `surface`.
pub fn is_reserved_field(name: &str, surface: FieldSurface) -> bool {
    matches!(
        field_use(name, surface),
        FieldUse::FrameworkOwned | FieldUse::Forbidden
    )
}

/// Returns a known alias on the requested surface.
pub fn field_alias(name: &str, surface: FieldSurface) -> Option<&'static FieldAlias> {
    FIELD_ALIASES
        .iter()
        .find(|alias| alias.name == name && alias.surfaces.contains(&surface))
}

fn family_definition(family: NamingFamily) -> &'static NamingFamilyDefinition {
    NAMING_FAMILIES
        .iter()
        .find(|definition| definition.family == family)
        .expect("every matcher references a registered naming family")
}

fn has_role_suffix(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len() && name.ends_with(suffix)
}

/// Classifies a role-qualified field by its most specific naming family.
pub fn field_family(name: &str) -> Option<&'static NamingFamilyDefinition> {
    let family = if name == "ip_address" || has_role_suffix(name, "_ip_address") {
        NamingFamily::IpAddress
    } else if name == "mac_address" || has_role_suffix(name, "_mac_address") {
        NamingFamily::MacAddress
    } else if has_role_suffix(name, "_address") {
        NamingFamily::NetworkAddress
    } else if has_role_suffix(name, "_state")
        || matches!(name, "previous_state" | "next_state" | "target_state")
    {
        NamingFamily::State
    } else if has_role_suffix(name, "_count") {
        NamingFamily::Count
    } else if [
        "_bytes",
        "_seconds",
        "_milliseconds",
        "_microseconds",
        "_nanoseconds",
    ]
    .iter()
    .any(|suffix| has_role_suffix(name, suffix))
    {
        NamingFamily::Quantity
    } else if has_role_suffix(name, "_id") {
        NamingFamily::Identifier
    } else {
        return None;
    };
    Some(family_definition(family))
}

/// Returns the key emitted by logfmt for a tracing source key.
///
/// Dotted semantic-convention keys are flattened with underscores. Callers
/// must compare this rendered form when detecting duplicate output keys.
pub fn rendered_field_name(name: &str) -> Cow<'_, str> {
    if name.contains('.') {
        Cow::Owned(name.replace('.', "_"))
    } else {
        Cow::Borrowed(name)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn field_name_grammar_is_surface_aware() {
        struct Case {
            scenario: &'static str,
            name: &'static str,
            surface: FieldSurface,
            valid: bool,
        }

        for case in [
            Case {
                scenario: "plain lower snake",
                name: "machine_id",
                surface: PLAIN,
                valid: true,
            },
            Case {
                scenario: "plain semantic convention",
                name: "db.statement",
                surface: PLAIN,
                valid: true,
            },
            Case {
                scenario: "span semantic convention",
                name: "rpc.grpc.status_code",
                surface: SPAN,
                valid: true,
            },
            Case {
                scenario: "legacy metric leading underscore",
                name: "_legacy9",
                surface: LABEL,
                valid: true,
            },
            Case {
                scenario: "legacy metric uppercase",
                name: "LegacyLabel",
                surface: LABEL,
                valid: true,
            },
            Case {
                scenario: "empty",
                name: "",
                surface: PLAIN,
                valid: false,
            },
            Case {
                scenario: "leading underscore in a log key",
                name: "_private",
                surface: TYPED,
                valid: false,
            },
            Case {
                scenario: "uppercase log key",
                name: "MachineId",
                surface: PLAIN,
                valid: false,
            },
            Case {
                scenario: "hyphenated log key",
                name: "machine-id",
                surface: SPAN,
                valid: false,
            },
            Case {
                scenario: "empty snake segment",
                name: "machine__id",
                surface: PLAIN,
                valid: false,
            },
            Case {
                scenario: "empty dotted segment",
                name: "rpc..status",
                surface: SPAN,
                valid: false,
            },
            Case {
                scenario: "metric labels cannot contain dots",
                name: "rpc.status",
                surface: LABEL,
                valid: false,
            },
        ] {
            assert_eq!(
                validate_field_name(case.name, case.surface).is_ok(),
                case.valid,
                "{}: {}",
                case.scenario,
                case.name
            );
        }
    }

    #[test]
    fn reserved_policies_are_surface_aware() {
        struct Case {
            scenario: &'static str,
            name: &'static str,
            surface: FieldSurface,
            usage: FieldUse,
        }

        for case in [
            Case {
                scenario: "component comes from span or subscriber on event lines",
                name: "component",
                surface: TYPED,
                usage: FieldUse::FrameworkOwned,
            },
            Case {
                scenario: "component is a legitimate span field",
                name: "component",
                surface: SPAN,
                usage: FieldUse::Allowed,
            },
            Case {
                scenario: "component is a bounded metric dimension",
                name: "component",
                surface: LABEL,
                usage: FieldUse::AllowedIfBounded,
            },
            Case {
                scenario: "span id is declared on spans",
                name: "span_id",
                surface: SPAN,
                usage: FieldUse::Allowed,
            },
            Case {
                scenario: "typed Event supplies event identity",
                name: "event_name",
                surface: TYPED,
                usage: FieldUse::FrameworkOwned,
            },
            Case {
                scenario: "frozen metric label keeps event identity spelling",
                name: "event_name",
                surface: LABEL,
                usage: FieldUse::CompatibilityOnly,
            },
            Case {
                scenario: "formatter owns span timing",
                name: "timing_elapsed_us",
                surface: SPAN,
                usage: FieldUse::FrameworkOwned,
            },
            Case {
                scenario: "same timing key is not reserved on an event",
                name: "timing_elapsed_us",
                surface: PLAIN,
                usage: FieldUse::Unspecified,
            },
            Case {
                scenario: "bounded reason enums remain valid Event labels",
                name: "reason",
                surface: LABEL,
                usage: FieldUse::AllowedIfBounded,
            },
            Case {
                scenario: "bounded command enums remain valid Event labels",
                name: "command",
                surface: LABEL,
                usage: FieldUse::AllowedIfBounded,
            },
        ] {
            assert_eq!(
                field_use(case.name, case.surface),
                case.usage,
                "{}",
                case.scenario
            );
        }
    }

    #[test]
    fn registry_is_open_for_domain_fields() {
        assert!(validate_field_name("firmware_slot", TYPED).is_ok());
        assert_eq!(field_use("firmware_slot", TYPED), FieldUse::Unspecified);
        assert!(field_definition("firmware_slot", TYPED).is_none());
        assert!(field_alias("firmware_slot", TYPED).is_none());
    }

    #[test]
    fn aliases_distinguish_safe_and_contextual_normalization() {
        let err = field_alias("err", PLAIN).expect("err is registered");
        assert_eq!(err.target, AliasTarget::Field("error"));
        assert_eq!(err.confidence, AliasConfidence::Unambiguous);
        assert!(field_alias("err", LABEL).is_none());

        let mac = field_alias("mac", TYPED).expect("mac is registered");
        assert_eq!(mac.target, AliasTarget::Field("mac_address"));
        assert_eq!(mac.confidence, AliasConfidence::ContextDependent);

        let addr = field_alias("addr", SPAN).expect("addr is registered");
        assert_eq!(
            addr.target,
            AliasTarget::Family(NamingFamily::NetworkAddress)
        );
    }

    #[test]
    fn naming_families_prefer_specific_suffixes() {
        for (name, expected) in [
            ("bmc_ip_address", Some(NamingFamily::IpAddress)),
            ("interface_mac_address", Some(NamingFamily::MacAddress)),
            ("peer_address", Some(NamingFamily::NetworkAddress)),
            ("machine_id", Some(NamingFamily::Identifier)),
            ("previous_state", Some(NamingFamily::State)),
            ("pending_partition_count", Some(NamingFamily::Count)),
            ("retry_delay_seconds", Some(NamingFamily::Quantity)),
            ("address", None),
            ("id", None),
            ("state", None),
            ("count", None),
        ] {
            assert_eq!(
                field_family(name).map(|definition| definition.family),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn rendered_names_expose_logfmt_collisions() {
        assert_eq!(
            rendered_field_name("rpc.grpc.status_code"),
            "rpc_grpc_status_code"
        );
        assert_eq!(rendered_field_name("machine_id"), "machine_id");
        assert_eq!(
            rendered_field_name("rpc.grpc.status_code"),
            rendered_field_name("rpc_grpc_status_code")
        );
    }

    #[test]
    fn registry_tables_are_internally_consistent() {
        let mut names = HashSet::new();
        for definitions in [RESERVED_FIELDS, COMMON_FIELDS] {
            assert!(
                definitions
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name),
                "field definitions stay sorted for deterministic reports"
            );
            for definition in definitions {
                assert!(
                    names.insert(definition.name),
                    "duplicate field definition: {}",
                    definition.name
                );
                let mut surfaces = HashSet::new();
                for rule in definition.surface_rules {
                    assert!(
                        surfaces.insert(rule.surface),
                        "duplicate {:?} rule for {}",
                        rule.surface,
                        definition.name
                    );
                    if rule.usage != FieldUse::Forbidden {
                        assert!(
                            validate_field_name(definition.name, rule.surface).is_ok(),
                            "{} is invalid on {:?}",
                            definition.name,
                            rule.surface
                        );
                    }
                }
            }
        }

        assert!(
            FIELD_ALIASES
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name),
            "aliases stay sorted for deterministic reports"
        );
        for alias in FIELD_ALIASES {
            match alias.target {
                AliasTarget::Field(name) => {
                    assert!(definition_by_name(name).is_some(), "missing target: {name}");
                    assert_ne!(alias.name, name);
                }
                AliasTarget::Family(family) => {
                    assert_eq!(family_definition(family).family, family);
                }
            }
            for surface in alias.surfaces {
                assert!(validate_field_name(alias.name, *surface).is_ok());
            }
        }

        let family_count = NAMING_FAMILIES
            .iter()
            .map(|definition| definition.family)
            .collect::<HashSet<_>>()
            .len();
        assert_eq!(family_count, NAMING_FAMILIES.len());
    }
}
