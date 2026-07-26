// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package eventrule defines the in-memory domain contracts for policy-driven
// event handling. It deliberately contains no event transport, database
// representation, inventory lookup, rule repository, or action executor.
// Those boundaries convert their own representations into these types.
//
// # Events
//
// Envelope is the normalized event accepted by processing. Its ID identifies
// one event across delivery retries, while CorrelationKey groups distinct
// observations of the same logical incident for optional semantic
// deduplication. Resource identifies the Flow rack or component concerned by
// the event. A resource may initially have only an ExternalID; enrichment can
// later populate its Flow ID and canonical component type.
//
// Envelope.Payload is opaque JSON whose schema is selected by Envelope.Type.
// The generic domain validates only that the payload is valid JSON. The child
// package that owns an event type defines its typed payload and strict
// encode/decode helpers when that event carries type-specific information. An
// event that needs only the common envelope fields leaves Payload nil.
//
// # Rules and policies
//
// Rule represents either a configurable persisted rule associated with scopes
// such as global or rack, or an immutable code-defined fallback. Rule.Origin
// distinguishes those sources; both use stable UUID identities and the same
// Policy, so processing executes them identically.
//
// EventType belongs to Rule because it controls rule selection. Policy contains
// only response behavior: optional deduplication and the actions considered for
// an accepted event. A resolver is
// expected to select one effective rule before its policy is evaluated, for
// example rack override, then global rule, then built-in fallback.
//
// # Actions
//
// Each Action has a stable ID within its policy, an optional Condition, and a
// concrete ActionSpec. Conditions intentionally support only
// demonstrated event properties: severity and component type. Values within
// one condition field use OR semantics, while different fields use AND
// semantics. An empty condition applies to every event.
//
// Task actions use a named TargetStrategy rather than an arbitrary inventory
// query. Target resolution and side effects occur outside this package. If a
// target strategy resolves no resources, the processor should record the
// action as skipped and must not submit a task.
//
// # Validation boundaries
//
// Collectors validate Envelope before handing it to processing. Repositories
// and APIs validate Rule when converting from their persistence or transport
// representations. Event-family code strictly validates any typed payload,
// and executors validate runtime requirements that depend on inventory or
// external services.
package eventrule
