// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package action encodes and decodes versioned persisted event-rule actions.
package action

import (
	"encoding/json"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec"
)

// Marshal encodes a current domain action using the latest persistence format.
func Marshal(action eventrule.Action) (json.RawMessage, error) {
	if err := action.Validate(); err != nil {
		return nil, err
	}

	return marshalActionV1(action)
}

// Unmarshal decodes any supported persisted action into the current domain.
func Unmarshal(data json.RawMessage) (eventrule.Action, error) {
	version, err := codec.DecodeVersion(data, "event action")
	if err != nil {
		return eventrule.Action{}, err
	}

	var action eventrule.Action
	switch version {
	case actionVersionV1:
		action, err = unmarshalActionV1(data)
		if err != nil {
			return eventrule.Action{}, err
		}
	default:
		return eventrule.Action{}, fmt.Errorf(
			"unknown event action version %d",
			version,
		)
	}

	if err := action.Validate(); err != nil {
		return eventrule.Action{}, fmt.Errorf("validate event action: %w", err)
	}

	return action, nil
}
