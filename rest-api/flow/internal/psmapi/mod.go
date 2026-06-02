// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package psmapi abstracts the GRPC interface used to communicate with the Powershelf Manager (PSM) service.
// New connection pools can be created with NewClient to create a real client or NewMockClient which fakes
// everything for unit tests.

package psmapi

import "context"

// Client allows us to have both a real implementation and a mock implementation for unit tests which can be switched transparently.
type Client interface {
	// GetPowershelves returns powershelf information for the specified PMC MAC addresses.
	// If pmcMacs is empty, returns all powershelves.
	GetPowershelves(ctx context.Context, pmcMacs []string) ([]PowerShelf, error)

	// RegisterPowershelves registers new powershelves with their PMC credentials.
	RegisterPowershelves(ctx context.Context, requests []RegisterPowershelfRequest) ([]RegisterPowershelfResponse, error)

	// PowerOn powers on the specified powershelves.
	PowerOn(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error)

	// PowerOff powers off the specified powershelves.
	PowerOff(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error)

	// UpdateFirmware performs firmware upgrades on the specified powershelves.
	UpdateFirmware(ctx context.Context, requests []UpdatePowershelfFirmwareRequest) ([]UpdatePowershelfFirmwareResponse, error)

	// GetFirmwareUpdateStatus returns the status of firmware updates for the specified PMC(s) and component(s).
	GetFirmwareUpdateStatus(ctx context.Context, queries []FirmwareUpdateQuery) ([]FirmwareUpdateStatus, error)

	// ListAvailableFirmware lists the firmware versions available for the specified powershelves.
	ListAvailableFirmware(ctx context.Context, pmcMacs []string) ([]AvailableFirmware, error)

	// SetDryRun configures whether the firmware manager is in Dry Run mode.
	SetDryRun(ctx context.Context, dryRun bool) error

	// Close closes the underlying gRPC connection.
	Close() error

	// The following are only valid in the mock environment and should only be called by unit tests.
	AddPowershelf(PowerShelf)
}
