// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type decommissionPowerShelfForgeClient struct {
	corev1.ForgeClient
	request *corev1.PowerShelfId
	err     error
}

func (c *decommissionPowerShelfForgeClient) DecommissionPowerShelf(
	_ context.Context,
	request *corev1.PowerShelfId,
	_ ...grpc.CallOption,
) (*emptypb.Empty, error) {
	c.request = request
	return &emptypb.Empty{}, c.err
}

func TestGrpcClient_DecommissionPowerShelf(t *testing.T) {
	tests := map[string]struct {
		clientError error
		wantError   string
	}{
		"success": {},
		"Core error": {
			clientError: errors.New("Core unavailable"),
			wantError:   "failed to decommission power shelf shelf-1: Core unavailable",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			forgeClient := &decommissionPowerShelfForgeClient{err: test.clientError}
			client := &grpcClient{
				gclient:     forgeClient,
				grpcTimeout: time.Second,
			}

			err := client.DecommissionPowerShelf(t.Context(), "shelf-1")
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.wantError)
			}

			assert.Equal(t, "shelf-1", forgeClient.request.GetId())
		})
	}
}
