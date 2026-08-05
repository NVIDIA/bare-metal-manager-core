// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package policycodec

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

const dedupeVersionV1 = 1

type dedupeV1 struct {
	Version int           `json:"version"`
	Window  time.Duration `json:"window"`
}

func marshalDedupeV1(dedupe eventrule.Dedupe) (json.RawMessage, error) {
	encoded, err := json.Marshal(dedupeV1{
		Version: dedupeVersionV1,
		Window:  dedupe.Window,
	})
	if err != nil {
		return nil, fmt.Errorf("encode event policy dedupe v1: %w", err)
	}
	return encoded, nil
}

func unmarshalDedupeV1(data json.RawMessage) (*eventrule.Dedupe, error) {
	var persisted dedupeV1
	if err := decodeStrict(data, &persisted); err != nil {
		return nil, fmt.Errorf("decode event policy dedupe v1: %w", err)
	}
	return &eventrule.Dedupe{Window: persisted.Window}, nil
}
