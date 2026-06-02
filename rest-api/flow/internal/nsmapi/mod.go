// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nsmapi abstracts the gRPC interface used to communicate with the NV-Switch Manager (NSM) service.
// New connection pools can be created with NewClient to create a real client or NewMockClient which fakes
// everything for unit tests.
package nsmapi

import "context"

// Client allows us to have both a real implementation and a mock implementation for unit tests which can be switched transparently.
type Client interface {
	// GetNVSwitches returns NV-Switch information for the specified switch UUIDs.
	// If uuids is empty, returns all registered switches.
	GetNVSwitches(ctx context.Context, uuids []string) ([]NVSwitchTray, error)

	// RegisterNVSwitches registers NV-Switch trays and returns service-generated UUIDs.
	RegisterNVSwitches(ctx context.Context, requests []RegisterNVSwitchRequest) ([]RegisterNVSwitchResponse, error)

	// PowerControl performs a power action on the specified NV-Switch trays.
	PowerControl(ctx context.Context, uuids []string, action PowerAction) ([]PowerControlResult, error)

	// QueueUpdates queues firmware updates for one or more components for multiple switches.
	// If components is empty, all components in the bundle are updated in sequence.
	QueueUpdates(ctx context.Context, switchUUIDs []string, bundleVersion string, components []NVSwitchComponent) ([]FirmwareUpdateInfo, error)

	// GetUpdates returns the status of firmware updates for a given switch.
	GetUpdates(ctx context.Context, switchUUID string) ([]FirmwareUpdateInfo, error)

	// ListBundles returns all available firmware bundles.
	ListBundles(ctx context.Context) ([]FirmwareBundle, error)

	// Close closes the underlying gRPC connection.
	Close() error

	// The following are only valid in the mock environment and should only be called by unit tests.
	AddNVSwitch(NVSwitchTray)
	SetNVSwitchFirmware(bmcMAC string, firmware string)
}
