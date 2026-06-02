// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psmapi

import (
	"context"
	"testing"
)

func TestMockClient_GetPowershelves(t *testing.T) {
	client := NewMockClient()

	// Add a powershelf
	client.AddPowershelf(PowerShelf{
		PMC: PowerManagementController{
			MACAddress:      "aa:bb:cc:dd:ee:ff",
			IPAddress:       "192.168.1.100",
			Vendor:          PMCVendorLiteon,
			FirmwareVersion: "1.0.0",
		},
		Chassis: Chassis{
			SerialNumber: "CHASSIS001",
			Model:        "PowerShelf-1000",
			Manufacturer: "TestMfg",
		},
		PSUs: []PowerSupplyUnit{
			{
				ID:         "PSU1",
				Name:       "Power Supply 1",
				PowerState: true,
			},
		},
	})

	ctx := context.Background()

	// Test getting all powershelves
	powershelves, err := client.GetPowershelves(ctx, nil)
	if err != nil {
		t.Fatalf("GetPowershelves failed: %v", err)
	}
	if len(powershelves) != 1 {
		t.Fatalf("Expected 1 powershelf, got %d", len(powershelves))
	}
	if powershelves[0].PMC.MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Expected MAC aa:bb:cc:dd:ee:ff, got %s", powershelves[0].PMC.MACAddress)
	}

	// Test getting specific powershelf
	powershelves, err = client.GetPowershelves(ctx, []string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("GetPowershelves failed: %v", err)
	}
	if len(powershelves) != 1 {
		t.Fatalf("Expected 1 powershelf, got %d", len(powershelves))
	}

	// Test getting non-existent powershelf
	powershelves, err = client.GetPowershelves(ctx, []string{"11:22:33:44:55:66"})
	if err != nil {
		t.Fatalf("GetPowershelves failed: %v", err)
	}
	if len(powershelves) != 0 {
		t.Fatalf("Expected 0 powershelves, got %d", len(powershelves))
	}
}

func TestMockClient_RegisterPowershelves(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()

	// Register a new powershelf
	requests := []RegisterPowershelfRequest{
		{
			PMCMACAddress: "aa:bb:cc:dd:ee:ff",
			PMCIPAddress:  "192.168.1.100",
			PMCVendor:     PMCVendorLiteon,
			PMCCredentials: Credentials{
				Username: "admin",
				Password: "password",
			},
		},
	}

	responses, err := client.RegisterPowershelves(ctx, requests)
	if err != nil {
		t.Fatalf("RegisterPowershelves failed: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(responses))
	}
	if !responses[0].IsNew {
		t.Error("Expected IsNew to be true for new registration")
	}
	if responses[0].Status != StatusSuccess {
		t.Errorf("Expected StatusSuccess, got %v", responses[0].Status)
	}

	// Register the same powershelf again
	responses, err = client.RegisterPowershelves(ctx, requests)
	if err != nil {
		t.Fatalf("RegisterPowershelves failed: %v", err)
	}
	if responses[0].IsNew {
		t.Error("Expected IsNew to be false for existing registration")
	}
}

func TestMockClient_PowerControl(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()
	pmcMacs := []string{"aa:bb:cc:dd:ee:ff"}

	// Test PowerOn
	results, err := client.PowerOn(ctx, pmcMacs)
	if err != nil {
		t.Fatalf("PowerOn failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusSuccess {
		t.Errorf("Expected StatusSuccess, got %v", results[0].Status)
	}

	// Test PowerOff
	results, err = client.PowerOff(ctx, pmcMacs)
	if err != nil {
		t.Fatalf("PowerOff failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusSuccess {
		t.Errorf("Expected StatusSuccess, got %v", results[0].Status)
	}
}

func TestMockClient_UpdateFirmware(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()

	requests := []UpdatePowershelfFirmwareRequest{
		{
			PMCMACAddress: "aa:bb:cc:dd:ee:ff",
			Components: []UpdateComponentFirmwareRequest{
				{
					Component: PowershelfComponentPMC,
					UpgradeTo: FirmwareVersion{Version: "2.0.0"},
				},
			},
		},
	}

	responses, err := client.UpdateFirmware(ctx, requests)
	if err != nil {
		t.Fatalf("UpdateFirmware failed: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(responses))
	}
	if len(responses[0].Components) != 1 {
		t.Fatalf("Expected 1 component response, got %d", len(responses[0].Components))
	}
	if responses[0].Components[0].Status != StatusSuccess {
		t.Errorf("Expected StatusSuccess, got %v", responses[0].Components[0].Status)
	}
}

func TestMockClient_GetFirmwareUpdateStatus(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()

	queries := []FirmwareUpdateQuery{
		{
			PMCMACAddress: "aa:bb:cc:dd:ee:ff",
			Component:     PowershelfComponentPMC,
		},
	}

	statuses, err := client.GetFirmwareUpdateStatus(ctx, queries)
	if err != nil {
		t.Fatalf("GetFirmwareUpdateStatus failed: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("Expected 1 status, got %d", len(statuses))
	}
	if statuses[0].State != FirmwareUpdateStateCompleted {
		t.Errorf("Expected FirmwareUpdateStateCompleted, got %v", statuses[0].State)
	}
}

func TestMockClient_ListAvailableFirmware(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()

	available, err := client.ListAvailableFirmware(ctx, []string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("ListAvailableFirmware failed: %v", err)
	}
	if len(available) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(available))
	}
	if len(available[0].Upgrades) == 0 {
		t.Error("Expected at least one upgrade path")
	}
}

func TestMockClient_SetDryRun(t *testing.T) {
	client := NewMockClient()
	ctx := context.Background()

	err := client.SetDryRun(ctx, true)
	if err != nil {
		t.Fatalf("SetDryRun failed: %v", err)
	}

	err = client.SetDryRun(ctx, false)
	if err != nil {
		t.Fatalf("SetDryRun failed: %v", err)
	}
}

func TestMockClient_Close(t *testing.T) {
	client := NewMockClient()

	err := client.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
