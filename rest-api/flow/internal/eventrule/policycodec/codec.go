// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package policycodec encodes and decodes versioned persisted event policies.
package policycodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

type versionHeader struct {
	Version int `json:"version"`
}

// Marshal encodes a current domain policy using the latest persistence format.
func Marshal(policy eventrule.Policy) (json.RawMessage, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	return marshalPolicy(policy)
}

// Unmarshal decodes any supported persisted policy into the current domain.
func Unmarshal(data json.RawMessage) (eventrule.Policy, error) {
	policy, err := unmarshalPolicy(data)
	if err != nil {
		return eventrule.Policy{}, err
	}

	if err := policy.Validate(); err != nil {
		return eventrule.Policy{}, fmt.Errorf("validate event policy: %w", err)
	}

	return policy, nil
}

func marshalPolicy(policy eventrule.Policy) (json.RawMessage, error) {
	return marshalPolicyV1(policy)
}

func unmarshalPolicy(data json.RawMessage) (eventrule.Policy, error) {
	version, err := decodeVersion(data, "event policy")
	if err != nil {
		return eventrule.Policy{}, err
	}

	switch version {
	case policyVersionV1:
		return unmarshalPolicyV1(data)
	default:
		return eventrule.Policy{}, fmt.Errorf("unknown event policy version %d", version)
	}
}

func marshalDedupe(dedupe eventrule.Dedupe) (json.RawMessage, error) {
	return marshalDedupeV1(dedupe)
}

func unmarshalDedupe(data json.RawMessage) (*eventrule.Dedupe, error) {
	version, err := decodeVersion(data, "event policy dedupe")
	if err != nil {
		return nil, err
	}

	switch version {
	case dedupeVersionV1:
		return unmarshalDedupeV1(data)
	default:
		return nil, fmt.Errorf("unknown event policy dedupe version %d", version)
	}
}

func marshalAction(action eventrule.Action) (json.RawMessage, error) {
	return marshalActionV1(action)
}

func unmarshalAction(data json.RawMessage) (eventrule.Action, error) {
	version, err := decodeVersion(data, "event policy action")
	if err != nil {
		return eventrule.Action{}, err
	}

	switch version {
	case actionVersionV1:
		return unmarshalActionV1(data)
	default:
		return eventrule.Action{}, fmt.Errorf("unknown event policy action version %d", version)
	}
}

func decodeVersion(data json.RawMessage, name string) (int, error) {
	var header versionHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return 0, fmt.Errorf("decode %s header: %w", name, err)
	}

	return header.Version, nil
}

func decodeStrict(data json.RawMessage, target any) error {
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
