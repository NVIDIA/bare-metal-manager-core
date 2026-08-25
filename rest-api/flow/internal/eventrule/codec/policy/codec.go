// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package policy encodes and decodes versioned persisted event policies.
package policy

import (
	"encoding/json"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec"
)

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
	version, err := codec.DecodeVersion(data, "event policy")
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
