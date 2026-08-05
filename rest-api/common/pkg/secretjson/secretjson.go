// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secretjson splits secret fields out of a JSON payload and merges them
// back.
//
// The generic Core and Flow gRPC proxies carry their protojson request bodies
// through Temporal history, where anyone with UI access can read them. Redact
// lifts the named fields out of that readable body on the cloud side so they
// can travel encrypted alongside it; Merge restores them on the site side after
// decryption, immediately before the gRPC call.
package secretjson

import (
	"encoding/json"
	"fmt"
	"maps"
)

// RedactedPlaceholder is the value substituted for a redacted secret field in
// the remaining readable JSON.
const RedactedPlaceholder = "[REDACTED]"

// Redact removes the named top-level fields from payload, replacing each present
// field with RedactedPlaceholder, and returns the redacted payload plus a JSON
// object of the extracted secret fields. fields are JSON (for protojson bodies,
// protojson) field names. When no named field is present, secretsJSON is nil and
// redacted equals the input.
func Redact(payload []byte, fields []string) (redacted []byte, secretsJSON []byte, err error) {
	if len(fields) == 0 {
		return payload, nil, nil
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, nil, fmt.Errorf("redact secrets: %w", err)
	}

	placeholder, err := json.Marshal(RedactedPlaceholder)
	if err != nil {
		return nil, nil, fmt.Errorf("redact secrets: %w", err)
	}

	secrets := make(map[string]json.RawMessage)
	for _, f := range fields {
		if v, ok := m[f]; ok {
			secrets[f] = v
			m[f] = placeholder
		}
	}
	if len(secrets) == 0 {
		return payload, nil, nil
	}

	redacted, err = json.Marshal(m)
	if err != nil {
		return nil, nil, fmt.Errorf("redact secrets: %w", err)
	}
	secretsJSON, err = json.Marshal(secrets)
	if err != nil {
		return nil, nil, fmt.Errorf("redact secrets: %w", err)
	}
	return redacted, secretsJSON, nil
}

// Merge overlays the secret fields back into a redacted payload, undoing Redact.
// An empty secretsJSON returns redacted unchanged.
func Merge(redacted []byte, secretsJSON []byte) ([]byte, error) {
	if len(secretsJSON) == 0 {
		return redacted, nil
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(redacted, &m); err != nil {
		return nil, fmt.Errorf("merge secrets: %w", err)
	}
	var secrets map[string]json.RawMessage
	if err := json.Unmarshal(secretsJSON, &secrets); err != nil {
		return nil, fmt.Errorf("merge secrets: %w", err)
	}

	maps.Copy(m, secrets)
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("merge secrets: %w", err)
	}
	return out, nil
}
