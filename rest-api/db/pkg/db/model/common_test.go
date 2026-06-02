// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

func TestLabels_FromProto(t *testing.T) {
	tests := []struct {
		name        string
		protoLabels []*cwssaws.Label
		want        Labels
	}{
		{
			name:        "nil slice clears receiver",
			protoLabels: nil,
			want:        nil,
		},
		{
			name:        "empty slice yields empty map",
			protoLabels: []*cwssaws.Label{},
			want:        Labels{},
		},
		{
			name: "single label with value",
			protoLabels: []*cwssaws.Label{
				{Key: "environment", Value: db.GetStrPtr("production")},
			},
			want: Labels{"environment": "production"},
		},
		{
			name: "multiple labels",
			protoLabels: []*cwssaws.Label{
				{Key: "environment", Value: db.GetStrPtr("production")},
				{Key: "rack", Value: db.GetStrPtr("rack-1")},
				{Key: "datacenter", Value: db.GetStrPtr("dc1")},
			},
			want: Labels{
				"environment": "production",
				"rack":        "rack-1",
				"datacenter":  "dc1",
			},
		},
		{
			name: "label with nil value yields empty string",
			protoLabels: []*cwssaws.Label{
				{Key: "flag", Value: nil},
			},
			want: Labels{"flag": ""},
		},
		{
			name: "label with empty key is skipped",
			protoLabels: []*cwssaws.Label{
				{Key: "", Value: db.GetStrPtr("value")},
				{Key: "valid", Value: db.GetStrPtr("data")},
			},
			want: Labels{"valid": "data"},
		},
		{
			name: "nil label entry is skipped",
			protoLabels: []*cwssaws.Label{
				nil,
				{Key: "valid", Value: db.GetStrPtr("data")},
			},
			want: Labels{"valid": "data"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got Labels
			got.FromProto(tc.protoLabels)
			if tc.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// TestLabels_FromProto_OverwritesExistingReceiver verifies that the
// method replaces the receiver wholesale, mirroring `ToProto` semantics:
// pre-existing entries are not preserved across calls. The pointer
// receiver makes the nil-input case observable (existing labels become
// nil), which mirrors how the workflow `Metadata.Labels` round-trips a
// "labels explicitly cleared" signal.
func TestLabels_FromProto_OverwritesExistingReceiver(t *testing.T) {
	t.Run("populated input replaces existing entries", func(t *testing.T) {
		l := Labels{"stale": "value", "kept-key": "old"}
		l.FromProto([]*cwssaws.Label{
			{Key: "kept-key", Value: db.GetStrPtr("new")},
			{Key: "fresh", Value: db.GetStrPtr("data")},
		})
		assert.Equal(t, Labels{"kept-key": "new", "fresh": "data"}, l)
	})

	t.Run("nil input clears existing entries", func(t *testing.T) {
		l := Labels{"stale": "value"}
		l.FromProto(nil)
		assert.Nil(t, l)
	})
}
