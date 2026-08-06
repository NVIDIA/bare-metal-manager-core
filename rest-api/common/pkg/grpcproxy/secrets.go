// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package grpcproxy

import (
	"encoding/json"
	"fmt"
	"maps"
)

// RedactedPlaceholder is the value substituted for a redacted secret field in
// the remaining readable JSON.
const RedactedPlaceholder = "[REDACTED]"

// RedactSecrets removes the named top-level fields from payload, replacing each
// present field with RedactedPlaceholder, and returns the redacted payload plus
// a JSON object of the extracted secret fields. fields are JSON (for protojson
// bodies, protojson) field names. When no named field is present, secretsJSON
// is nil and redacted equals the input.
//
// The proxies carry their request bodies through Temporal history, where anyone
// with UI access can read them, so the cloud lifts secret fields out of that
// readable body and sends them encrypted alongside it.
func RedactSecrets(payload []byte, fields []string) (redacted []byte, secretsJSON []byte, err error) {
	if len(fields) == 0 {
		return payload, nil, nil
	}

	var m map[string]json.RawMessage
	unmarshalErr := json.Unmarshal(payload, &m)
	if unmarshalErr != nil {
		return nil, nil, fmt.Errorf("redact secrets: %w", unmarshalErr)
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

// MergeSecrets overlays the secret fields back into a redacted payload, undoing
// RedactSecrets. The site calls it after decryption, immediately before the
// gRPC call. An empty secretsJSON returns redacted unchanged.
func MergeSecrets(redacted []byte, secretsJSON []byte) ([]byte, error) {
	if len(secretsJSON) == 0 {
		return redacted, nil
	}

	var m map[string]json.RawMessage
	redactedErr := json.Unmarshal(redacted, &m)
	if redactedErr != nil {
		return nil, fmt.Errorf("merge secrets: %w", redactedErr)
	}
	var secrets map[string]json.RawMessage
	secretsErr := json.Unmarshal(secretsJSON, &secrets)
	if secretsErr != nil {
		return nil, fmt.Errorf("merge secrets: %w", secretsErr)
	}

	maps.Copy(m, secrets)
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("merge secrets: %w", err)
	}
	return out, nil
}
