// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

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
