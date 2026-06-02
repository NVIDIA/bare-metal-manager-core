// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psmapi

import (
	"context"
	"time"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/common/utils"
)

type mockClient struct {
	powershelves map[string]PowerShelf
}

// NewMockClient returns a "GRPC" client that returns mock values so it can be used in unit tests.
func NewMockClient() Client {
	return &mockClient{powershelves: map[string]PowerShelf{}}
}

func (c *mockClient) Close() error {
	return nil
}

func (c *mockClient) GetPowershelves(_ context.Context, pmcMacs []string) ([]PowerShelf, error) {
	var result []PowerShelf

	if len(pmcMacs) == 0 {
		for _, ps := range c.powershelves {
			result = append(result, ps)
		}
	} else {
		for _, mac := range pmcMacs {
			if ps, ok := c.powershelves[utils.NormalizeMAC(mac)]; ok {
				result = append(result, ps)
			}
		}
	}

	return result, nil
}

func (c *mockClient) RegisterPowershelves(_ context.Context, requests []RegisterPowershelfRequest) ([]RegisterPowershelfResponse, error) {
	var result []RegisterPowershelfResponse

	for _, req := range requests {
		key := utils.NormalizeMAC(req.PMCMACAddress)
		_, exists := c.powershelves[key]
		isNew := !exists

		if isNew {
			c.powershelves[key] = PowerShelf{
				PMC: PowerManagementController{
					MACAddress: req.PMCMACAddress,
					IPAddress:  req.PMCIPAddress,
					Vendor:     req.PMCVendor,
				},
			}
		}

		result = append(result, RegisterPowershelfResponse{
			PMCMACAddress: req.PMCMACAddress,
			IsNew:         isNew,
			Created:       time.Now(),
			Status:        StatusSuccess,
		})
	}

	return result, nil
}

func (c *mockClient) PowerOn(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error) {
	var result []PowerControlResult
	for _, mac := range pmcMacs {
		result = append(result, PowerControlResult{
			PMCMACAddress: mac,
			Status:        StatusSuccess,
		})
	}
	return result, nil
}

func (c *mockClient) PowerOff(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error) {
	var result []PowerControlResult
	for _, mac := range pmcMacs {
		result = append(result, PowerControlResult{
			PMCMACAddress: mac,
			Status:        StatusSuccess,
		})
	}
	return result, nil
}

func (c *mockClient) UpdateFirmware(ctx context.Context, requests []UpdatePowershelfFirmwareRequest) ([]UpdatePowershelfFirmwareResponse, error) {
	var result []UpdatePowershelfFirmwareResponse
	for _, req := range requests {
		resp := UpdatePowershelfFirmwareResponse{
			PMCMACAddress: req.PMCMACAddress,
		}
		for _, comp := range req.Components {
			resp.Components = append(resp.Components, UpdateComponentFirmwareResponse{
				Component: comp.Component,
				Status:    StatusSuccess,
			})
		}
		result = append(result, resp)
	}
	return result, nil
}

func (c *mockClient) GetFirmwareUpdateStatus(ctx context.Context, queries []FirmwareUpdateQuery) ([]FirmwareUpdateStatus, error) {
	var result []FirmwareUpdateStatus
	for _, q := range queries {
		result = append(result, FirmwareUpdateStatus{
			PMCMACAddress: q.PMCMACAddress,
			Component:     q.Component,
			State:         FirmwareUpdateStateCompleted,
			Status:        StatusSuccess,
		})
	}
	return result, nil
}

func (c *mockClient) ListAvailableFirmware(ctx context.Context, pmcMacs []string) ([]AvailableFirmware, error) {
	var result []AvailableFirmware
	for _, mac := range pmcMacs {
		result = append(result, AvailableFirmware{
			PMCMACAddress: mac,
			Upgrades: []ComponentFirmwareUpgrades{
				{
					Component: PowershelfComponentPMC,
					Upgrades: []FirmwareVersion{
						{Version: "1.0.0"},
						{Version: "1.1.0"},
					},
				},
			},
		})
	}
	return result, nil
}

func (c *mockClient) SetDryRun(ctx context.Context, dryRun bool) error {
	return nil
}

func (c *mockClient) AddPowershelf(ps PowerShelf) {
	c.powershelves[utils.NormalizeMAC(ps.PMC.MACAddress)] = ps
}
