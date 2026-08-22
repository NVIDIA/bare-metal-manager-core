// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

func TestRackFromProto(t *testing.T) {
	domainIDs := []uuid.UUID{uuid.New(), uuid.New()}

	tests := []struct {
		name string
		rack *pb.Rack
		want []uuid.UUID
	}{
		{
			name: "nil rack",
			rack: nil,
			want: nil,
		},
		{
			name: "rack without domain membership",
			rack: &pb.Rack{},
			want: []uuid.UUID{},
		},
		{
			name: "rack with domain memberships",
			rack: &pb.Rack{NvlDomainIds: uuidsToProto(domainIDs)},
			want: domainIDs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rackFromProto(tt.rack)
			if tt.rack == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, got.NVLDomainIDs)
		})
	}
}

func TestRackToProto(t *testing.T) {
	domainIDs := []uuid.UUID{uuid.New(), uuid.New()}

	tests := []struct {
		name string
		rack *types.Rack
		want []*pb.UUID
	}{
		{
			name: "nil rack",
			rack: nil,
			want: nil,
		},
		{
			name: "rack without NVLink domain",
			rack: &types.Rack{},
			want: []*pb.UUID{},
		},
		{
			name: "rack with NVLink domains",
			rack: &types.Rack{NVLDomainIDs: domainIDs},
			want: uuidsToProto(domainIDs),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rackToProto(tt.rack)
			if tt.rack == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, got.GetNvlDomainIds())
		})
	}
}

func TestComponentNVLDomainIDRoundTrip(t *testing.T) {
	domainID := uuid.New()
	tests := []struct {
		name string
		id   uuid.UUID
	}{
		{name: "no domain membership"},
		{name: "domain membership", id: domainID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protoID := uuidToProto(tt.id)
			converted := componentFromProto(&pb.Component{NvlDomainId: protoID})
			assert.Equal(t, tt.id, converted.NVLDomainID)
			assert.Equal(t, protoID, componentToProto(converted).GetNvlDomainId())
		})
	}
}
