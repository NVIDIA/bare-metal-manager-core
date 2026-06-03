// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package simple

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToStandardInstanceUpdateRequest verifies that nil slice/map fields in an
// InstanceUpdateRequest are NOT forwarded to the standard API request. Forwarding nil as an empty
// slice causes the backend to clear the corresponding attribute (the original reported bug).
func TestToStandardInstanceUpdateRequest(t *testing.T) {
	t.Run("partial update with only NVLinkInterfaces set leaves IB and DES nil", func(t *testing.T) {
		req := InstanceUpdateRequest{
			NVLinkInterfaces: []NVLinkInterfaceCreateOrUpdateRequest{
				{NVLinkLogicalPartitionID: "nvlink-partition-1"},
			},
		}

		apiReq := toStandardInstanceUpdateRequest(req)

		// NVLink must be populated
		require.NotNil(t, apiReq.NvLinkInterfaces)
		assert.Len(t, apiReq.NvLinkInterfaces, 1)

		// InfiniBand and DES must stay nil so they are omitted from the JSON body
		assert.Nil(t, apiReq.InfinibandInterfaces,
			"InfinibandInterfaces must be nil when not set, to avoid clearing existing IB interfaces on the server")
		assert.Nil(t, apiReq.DpuExtensionServiceDeployments,
			"DpuExtensionServiceDeployments must be nil when not set")

		// Ensure the standard SDK's ToMap omits the unset fields entirely
		body, err := apiReq.ToMap()
		require.NoError(t, err)
		assert.Contains(t, body, "nvLinkInterfaces")
		assert.NotContains(t, body, "infinibandInterfaces",
			"infinibandInterfaces must not appear in the serialized request when not provided")
		assert.NotContains(t, body, "dpuExtensionServiceDeployments",
			"dpuExtensionServiceDeployments must not appear in the serialized request when not provided")
	})

	t.Run("partial update with only InfinibandInterfaces set leaves NVLink and DES nil", func(t *testing.T) {
		req := InstanceUpdateRequest{
			InfinibandInterfaces: []InfiniBandInterfaceCreateOrUpdateRequest{
				{
					PartitionID:    "ib-partition-1",
					Device:         "mlx5_0",
					DeviceInstance: 0,
					IsPhysical:     true,
				},
			},
		}

		apiReq := toStandardInstanceUpdateRequest(req)

		require.NotNil(t, apiReq.InfinibandInterfaces)
		assert.Len(t, apiReq.InfinibandInterfaces, 1)
		assert.Nil(t, apiReq.NvLinkInterfaces,
			"NvLinkInterfaces must be nil when not set, to avoid clearing existing NVLink interfaces on the server")
		assert.Nil(t, apiReq.DpuExtensionServiceDeployments)

		body, err := apiReq.ToMap()
		require.NoError(t, err)
		assert.Contains(t, body, "infinibandInterfaces")
		assert.NotContains(t, body, "nvLinkInterfaces")
		assert.NotContains(t, body, "dpuExtensionServiceDeployments")
	})

	t.Run("partial update with nil Labels leaves labels nil", func(t *testing.T) {
		name := "new-name"
		req := InstanceUpdateRequest{
			Name: &name,
		}

		apiReq := toStandardInstanceUpdateRequest(req)

		assert.Nil(t, apiReq.Labels,
			"Labels must be nil when not set, to avoid clearing existing labels on the server")

		body, err := apiReq.ToMap()
		require.NoError(t, err)
		assert.NotContains(t, body, "labels")
	})

	t.Run("explicit empty slice is forwarded as empty array to clear existing entries", func(t *testing.T) {
		req := InstanceUpdateRequest{
			// Explicitly setting to an empty (non-nil) slice signals intent to clear
			InfinibandInterfaces: []InfiniBandInterfaceCreateOrUpdateRequest{},
		}

		apiReq := toStandardInstanceUpdateRequest(req)

		// An explicit empty slice must be forwarded (non-nil) so the server clears the list
		require.NotNil(t, apiReq.InfinibandInterfaces,
			"An explicit empty InfinibandInterfaces slice must be forwarded to clear existing entries")
		assert.Empty(t, apiReq.InfinibandInterfaces)

		body, err := apiReq.ToMap()
		require.NoError(t, err)
		assert.Contains(t, body, "infinibandInterfaces")
	})

	t.Run("full update with all slice and map fields set", func(t *testing.T) {
		name := "my-instance"
		req := InstanceUpdateRequest{
			Name:   &name,
			Labels: map[string]string{"env": "prod"},
			InfinibandInterfaces: []InfiniBandInterfaceCreateOrUpdateRequest{
				{PartitionID: "ib-1", Device: "mlx5_0", DeviceInstance: 0, IsPhysical: true},
			},
			NVLinkInterfaces: []NVLinkInterfaceCreateOrUpdateRequest{
				{NVLinkLogicalPartitionID: "nvlink-1"},
			},
			DpuExtensionServiceDeployments: []DpuExtensionServiceDeploymentRequest{},
		}

		apiReq := toStandardInstanceUpdateRequest(req)

		assert.NotNil(t, apiReq.InfinibandInterfaces)
		assert.Len(t, apiReq.InfinibandInterfaces, 1)
		assert.NotNil(t, apiReq.NvLinkInterfaces)
		assert.Len(t, apiReq.NvLinkInterfaces, 1)
		assert.NotNil(t, apiReq.DpuExtensionServiceDeployments)
		assert.Empty(t, apiReq.DpuExtensionServiceDeployments)
		assert.NotNil(t, apiReq.Labels)

		body, err := apiReq.ToMap()
		require.NoError(t, err)
		assert.Contains(t, body, "infinibandInterfaces")
		assert.Contains(t, body, "nvLinkInterfaces")
		assert.Contains(t, body, "dpuExtensionServiceDeployments")
		assert.Contains(t, body, "labels")
	})
}
