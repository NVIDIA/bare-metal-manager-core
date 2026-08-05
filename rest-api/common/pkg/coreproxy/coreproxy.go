// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package coreproxy holds the contract shared between the cloud REST API and
// the on-site agent for the generic NICo Core gRPC proxy.
//
// Instead of a bespoke Temporal workflow + activity + typed request for every
// Core-backed REST operation, curated REST handlers can validate their input,
// build typed forge.Forge requests, and dispatch each Core invocation through
// this generic workflow. A single REST request may dispatch zero, one, or many
// proxied Core calls; this package defines the transport for one such call. The
// on-site site-agent worker runs a generic activity that performs the actual
// gRPC call against Core. The REST surface stays curated and designed; this is
// purely the internal cloud->site transport.
//
// The request/response payloads are carried as protojson (json.RawMessage) so
// they render as readable JSON in the Temporal UI. Secret fields (e.g. a BMC
// credential password) are redacted from that readable JSON with the secretjson
// package and carried separately as an AES-GCM ciphertext (EncryptedSecrets) so
// they never appear in Temporal history in cleartext; the site decrypts and
// merges them back before the Core call.
package coreproxy

import (
	"encoding/json"
	"time"
)

const (
	// WorkflowName is the Temporal workflow type registered by the site-agent
	// and started by the cloud REST API. It must match the workflow function
	// name in site-workflow/pkg/workflow (InvokeCoreGRPC).
	WorkflowName = "InvokeCoreGRPC"

	// ActivityStartToCloseTimeout bounds the on-site Core request before the
	// workflow and REST caller time out.
	ActivityStartToCloseTimeout = 40 * time.Second

	// WorkflowExecutionTimeout leaves the REST caller time to observe and
	// translate a terminal workflow result.
	WorkflowExecutionTimeout = 45 * time.Second
)

// Request is the generic proxy workflow/activity input.
type Request struct {
	// FullMethod is the gRPC method, either fully qualified
	// ("/forge.Forge/CreateCredential") or bare ("CreateCredential").
	FullMethod string `json:"fullMethod"`

	// RequestJSON is the protojson-encoded forge.Forge request message with
	// secret fields redacted. Kept as json.RawMessage so it is human-readable
	// in the Temporal UI.
	RequestJSON json.RawMessage `json:"requestJson,omitempty"`

	// EncryptedSecrets is the AES-GCM ciphertext of the redacted secret fields
	// (a JSON object of fieldName -> value). It is opaque (base64) in Temporal
	// history; the site decrypts it with the shared site key and merges the
	// values back into RequestJSON before invoking Core.
	EncryptedSecrets []byte `json:"encryptedSecrets,omitempty"`
}

// Response is the generic proxy workflow/activity output.
type Response struct {
	// ResponseJSON is the protojson-encoded forge.Forge response message.
	ResponseJSON json.RawMessage `json:"responseJson,omitempty"`
}
