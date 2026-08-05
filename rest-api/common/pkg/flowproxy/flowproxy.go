// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package flowproxy holds the contract shared between the cloud REST API and
// the on-site agent for the generic Flow gRPC proxy.
//
// Instead of a bespoke Temporal workflow + activity + typed request for every
// Flow-backed REST operation, curated REST handlers can validate their input,
// build typed v1.Flow requests, and dispatch each Flow invocation through this
// generic workflow. Unlike the Core proxy, callers supply the Temporal workflow
// ID and conflict policy so read dedup (USE_EXISTING + deterministic IDs) and
// create freshness (per-request UUIDs) stay under handler control.
//
// The request/response payloads are carried as protojson (json.RawMessage) so
// they render as readable JSON in the Temporal UI. Secret fields are redacted
// from that readable JSON with the secretjson package and carried separately as
// AES-GCM ciphertext (EncryptedSecrets); the site decrypts and merges them back
// before the Flow call.
package flowproxy

import (
	"encoding/json"
	"time"
)

const (
	// WorkflowName is the Temporal workflow type registered by the site-agent
	// and started by the cloud REST API. It must match the workflow function
	// name in site-workflow/pkg/workflow (InvokeFlowGRPC).
	WorkflowName = "InvokeFlowGRPC"

	// ActivityStartToCloseTimeout bounds the on-site Flow request before the
	// workflow and REST caller time out.
	ActivityStartToCloseTimeout = 40 * time.Second

	// WorkflowExecutionTimeout leaves the REST caller time to observe and
	// translate a terminal workflow result.
	//
	// The whole ladder must stay under the API server's write timeout: the
	// caller waits cutil.WorkflowContextTimeout, and a response written after
	// the server's write deadline never reaches the client. Nothing here may
	// exceed that deadline, however generous the on-site budget looks.
	WorkflowExecutionTimeout = 45 * time.Second
)

// Request is the generic proxy workflow/activity input.
type Request struct {
	// FullMethod is the gRPC method, either fully qualified
	// ("/v1.Flow/CreateOperationRun") or bare ("CreateOperationRun").
	FullMethod string `json:"fullMethod"`

	// RequestJSON is the protojson-encoded v1.Flow request message with secret
	// fields redacted. Kept as json.RawMessage so it is human-readable in the
	// Temporal UI.
	RequestJSON json.RawMessage `json:"requestJson,omitempty"`

	// EncryptedSecrets is the AES-GCM ciphertext of the redacted secret fields
	// (a JSON object of fieldName -> value). It is opaque (base64) in Temporal
	// history; the site decrypts it with the shared site key and merges the
	// values back into RequestJSON before invoking Flow.
	EncryptedSecrets []byte `json:"encryptedSecrets,omitempty"`
}

// Response is the generic proxy workflow/activity output.
type Response struct {
	// ResponseJSON is the protojson-encoded v1.Flow response message.
	ResponseJSON json.RawMessage `json:"responseJson,omitempty"`
}
