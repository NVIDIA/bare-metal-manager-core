// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package codec provides shared JSON decoding primitives for event-rule codecs.
package codec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type versionHeader struct {
	Version int `json:"version"`
}

// DecodeVersion reads the version field from a persisted JSON document.
func DecodeVersion(data json.RawMessage, name string) (int, error) {
	var header versionHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return 0, fmt.Errorf("decode %s header: %w", name, err)
	}

	return header.Version, nil
}

// DecodeStrict decodes one JSON value and rejects unknown fields and trailing
// values.
func DecodeStrict(data json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}

	return nil
}
