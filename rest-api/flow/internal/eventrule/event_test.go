// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"encoding/json"
	"testing"

	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestParseSeverity(t *testing.T) {
	tests := map[string]struct {
		value    string
		expected Severity
		wantErr  bool
	}{
		"unspecified": {expected: SeverityUnspecified},
		"info":        {value: "info", expected: SeverityInfo},
		"warning":     {value: "warning", expected: SeverityWarning},
		"critical":    {value: "critical", expected: SeverityCritical},
		"invalid":     {value: "urgent", wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseSeverity(test.value)
			if test.wantErr {
				require.Error(t, err)
				require.Equal(t, SeverityUnspecified, actual)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestEnvelopeValidatePayload(t *testing.T) {
	tests := map[string]struct {
		payload json.RawMessage
		wantErr string
	}{
		"valid payload": {
			payload: json.RawMessage(`{"value":42}`),
		},
		"invalid payload": {
			payload: json.RawMessage(`{"value":`),
			wantErr: "payload must be valid JSON",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := Envelope{
				ID:       uuid.New(),
				Type:     "test.event",
				Resource: Resource{Kind: ResourceKindRack},
				Payload:  test.payload,
			}

			err := envelope.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnvelopeAllowsUnspecifiedSeverity(t *testing.T) {
	envelope := Envelope{
		ID:       uuid.New(),
		Type:     "test.event",
		Severity: SeverityUnspecified,
		Resource: Resource{Kind: ResourceKindRack},
	}
	require.NoError(t, envelope.Validate())
}

func TestResourceIDMayBeUnresolved(t *testing.T) {
	resource := Resource{Kind: ResourceKindRack}
	require.Equal(t, uuid.Nil, resource.ID)
	require.NoError(t, resource.Validate())

	resource.ID = uuid.New()
	require.NoError(t, resource.Validate())
}

func TestResolvedResource_Validate(t *testing.T) {
	componentID := uuid.New()
	rackID := uuid.New()
	tests := []struct {
		name     string
		resource ResolvedResource
		wantErr  string
	}{
		{
			name: "component",
			resource: ResolvedResource{
				Kind:          ResourceKindComponent,
				ID:            componentID,
				RackID:        rackID,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		},
		{
			name: "rack",
			resource: ResolvedResource{
				Kind:   ResourceKindRack,
				ID:     rackID,
				RackID: rackID,
			},
		},
		{
			name: "rack ignores component type",
			resource: ResolvedResource{
				Kind:          ResourceKindRack,
				ID:            rackID,
				RackID:        rackID,
				ComponentType: flowtypes.ComponentTypeCompute,
			},
		},
		{
			name:     "kind required",
			resource: ResolvedResource{ID: componentID, RackID: rackID},
			wantErr:  "unknown resource kind",
		},
		{
			name:     "id required",
			resource: ResolvedResource{Kind: ResourceKindComponent, RackID: rackID},
			wantErr:  "resolved resource id is required",
		},
		{
			name:     "rack id required",
			resource: ResolvedResource{Kind: ResourceKindComponent, ID: componentID},
			wantErr:  "resolved resource rack id is required",
		},
		{
			name: "component type required",
			resource: ResolvedResource{
				Kind:   ResourceKindComponent,
				ID:     componentID,
				RackID: rackID,
			},
			wantErr: "resolved resource component type",
		},
		{
			name: "component type must be supported",
			resource: ResolvedResource{
				Kind:          ResourceKindComponent,
				ID:            componentID,
				RackID:        rackID,
				ComponentType: flowtypes.ComponentType("INVALID"),
			},
			wantErr: "unknown component type",
		},
		{
			name: "rack identities must match",
			resource: ResolvedResource{
				Kind:   ResourceKindRack,
				ID:     uuid.New(),
				RackID: rackID,
			},
			wantErr: "resolved rack resource id must equal rack id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.resource.Validate()
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
