// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nsmapi

import (
	"context"
	"time"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
	"github.com/google/uuid"
)

type mockClient struct {
	switches map[string]NVSwitchTray // keyed by BMC MAC
}

// NewMockClient returns a gRPC client that returns mock values so it can be used in unit tests.
func NewMockClient() Client {
	return &mockClient{
		switches: make(map[string]NVSwitchTray),
	}
}

func (c *mockClient) Close() error {
	return nil
}

func (c *mockClient) GetNVSwitches(_ context.Context, uuids []string) ([]NVSwitchTray, error) {
	if len(uuids) == 0 {
		results := make([]NVSwitchTray, 0, len(c.switches))
		for _, sw := range c.switches {
			results = append(results, sw)
		}
		return results, nil
	}
	uuidSet := make(map[string]struct{}, len(uuids))
	for _, u := range uuids {
		uuidSet[u] = struct{}{}
	}
	var results []NVSwitchTray
	for _, sw := range c.switches {
		if _, ok := uuidSet[sw.UUID]; ok {
			results = append(results, sw)
		}
	}
	return results, nil
}

func (c *mockClient) RegisterNVSwitches(_ context.Context, requests []RegisterNVSwitchRequest) ([]RegisterNVSwitchResponse, error) {
	var results []RegisterNVSwitchResponse
	for _, req := range requests {
		key := utils.NormalizeMAC(req.BMCMACAddress)
		if existing, ok := c.switches[key]; ok {
			results = append(results, RegisterNVSwitchResponse{
				UUID:   existing.UUID,
				IsNew:  false,
				Status: StatusSuccess,
			})
		} else {
			newUUID := uuid.New().String()
			c.switches[key] = NVSwitchTray{
				UUID:          newUUID,
				BMCMACAddress: req.BMCMACAddress,
				BMCIPAddress:  req.BMCIPAddress,
			}
			results = append(results, RegisterNVSwitchResponse{
				UUID:   newUUID,
				IsNew:  true,
				Status: StatusSuccess,
			})
		}
	}
	return results, nil
}

func (c *mockClient) AddNVSwitch(sw NVSwitchTray) {
	c.switches[utils.NormalizeMAC(sw.BMCMACAddress)] = sw
}

func (c *mockClient) SetNVSwitchFirmware(bmcMAC string, firmware string) {
	key := utils.NormalizeMAC(bmcMAC)
	if sw, ok := c.switches[key]; ok {
		sw.BMCFirmware = firmware
		c.switches[key] = sw
	}
}

func (c *mockClient) PowerControl(_ context.Context, uuids []string, _ PowerAction) ([]PowerControlResult, error) {
	var results []PowerControlResult
	for _, id := range uuids {
		results = append(results, PowerControlResult{
			UUID:   id,
			Status: StatusSuccess,
		})
	}
	return results, nil
}

func (c *mockClient) QueueUpdates(_ context.Context, switchUUIDs []string, bundleVersion string, components []NVSwitchComponent) ([]FirmwareUpdateInfo, error) {
	if len(components) == 0 {
		components = []NVSwitchComponent{
			NVSwitchComponentBMC,
			NVSwitchComponentCPLD,
			NVSwitchComponentBIOS,
			NVSwitchComponentNVOS,
		}
	}

	var results []FirmwareUpdateInfo
	for _, switchUUID := range switchUUIDs {
		for i, comp := range components {
			results = append(results, FirmwareUpdateInfo{
				ID:            uuid.New().String(),
				SwitchUUID:    switchUUID,
				Component:     comp,
				BundleVersion: bundleVersion,
				State:         UpdateStateQueued,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				SequenceOrder: int32(i + 1),
			})
		}
	}
	return results, nil
}

func (c *mockClient) GetUpdates(_ context.Context, switchUUID string) ([]FirmwareUpdateInfo, error) {
	return []FirmwareUpdateInfo{
		{
			ID:         uuid.New().String(),
			SwitchUUID: switchUUID,
			State:      UpdateStateCompleted,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}, nil
}

func (c *mockClient) ListBundles(_ context.Context) ([]FirmwareBundle, error) {
	return []FirmwareBundle{
		{
			Version:     "1.0.0",
			Description: "Mock firmware bundle",
			Components: []ComponentInfo{
				{Name: "BMC", Version: "1.0.0", Strategy: "redfish"},
				{Name: "CPLD", Version: "1.0.0", Strategy: "ssh"},
				{Name: "BIOS", Version: "1.0.0", Strategy: "redfish"},
				{Name: "NVOS", Version: "1.0.0", Strategy: "ssh"},
			},
		},
	}, nil
}
