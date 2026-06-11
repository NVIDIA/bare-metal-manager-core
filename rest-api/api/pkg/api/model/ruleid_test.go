// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequestRuleIDValidation exercises the ruleId field across all the
// rack/tray operation request models that grew it. The eight types are
// validated through three different code paths (ozzo-validation struct chain,
// inline check, mixed) but converge on the same "nil or valid UUID" contract.
func TestRequestRuleIDValidation(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	badUUID := "not-a-uuid"

	tests := []struct {
		name        string
		validate    func() error
		wantErr     bool
		errContains string
	}{
		// ---- power.go ----
		{
			name: "APIUpdatePowerStateRequest - bad ruleId",
			validate: func() error {
				return (&APIUpdatePowerStateRequest{SiteID: "s", State: "on", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIUpdatePowerStateRequest - valid ruleId",
			validate: func() error {
				return (&APIUpdatePowerStateRequest{SiteID: "s", State: "on", RuleID: &validUUID}).Validate()
			},
		},
		{
			name: "APIBatchUpdateRackPowerStateRequest - bad ruleId",
			validate: func() error {
				return (&APIBatchUpdateRackPowerStateRequest{SiteID: "s", State: "on", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBatchUpdateRackPowerStateRequest - valid ruleId",
			validate: func() error {
				return (&APIBatchUpdateRackPowerStateRequest{SiteID: "s", State: "on", RuleID: &validUUID}).Validate()
			},
		},
		{
			name: "APIBatchUpdateTrayPowerStateRequest - bad ruleId",
			validate: func() error {
				return (&APIBatchUpdateTrayPowerStateRequest{SiteID: "s", State: "on", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBatchUpdateTrayPowerStateRequest - valid ruleId",
			validate: func() error {
				return (&APIBatchUpdateTrayPowerStateRequest{SiteID: "s", State: "on", RuleID: &validUUID}).Validate()
			},
		},
		// ---- firmware.go ----
		{
			name: "APIUpdateFirmwareRequest - bad ruleId",
			validate: func() error {
				return (&APIUpdateFirmwareRequest{SiteID: "s", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIUpdateFirmwareRequest - valid ruleId",
			validate: func() error {
				return (&APIUpdateFirmwareRequest{SiteID: "s", RuleID: &validUUID}).Validate()
			},
		},
		{
			name: "APIBatchRackFirmwareUpdateRequest - bad ruleId",
			validate: func() error {
				return (&APIBatchRackFirmwareUpdateRequest{SiteID: "s", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBatchRackFirmwareUpdateRequest - valid ruleId",
			validate: func() error {
				return (&APIBatchRackFirmwareUpdateRequest{SiteID: "s", RuleID: &validUUID}).Validate()
			},
		},
		{
			name: "APIBatchTrayFirmwareUpdateRequest - bad ruleId",
			validate: func() error {
				return (&APIBatchTrayFirmwareUpdateRequest{SiteID: "s", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBatchTrayFirmwareUpdateRequest - valid ruleId",
			validate: func() error {
				return (&APIBatchTrayFirmwareUpdateRequest{SiteID: "s", RuleID: &validUUID}).Validate()
			},
		},
		// ---- rack.go (bring-up) ----
		{
			name: "APIBringUpRackRequest - bad ruleId",
			validate: func() error {
				return (&APIBringUpRackRequest{SiteID: "s", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBringUpRackRequest - valid ruleId",
			validate: func() error {
				return (&APIBringUpRackRequest{SiteID: "s", RuleID: &validUUID}).Validate()
			},
		},
		{
			name: "APIBatchBringUpRackRequest - bad ruleId",
			validate: func() error {
				return (&APIBatchBringUpRackRequest{SiteID: "s", RuleID: &badUUID}).Validate()
			},
			wantErr:     true,
			errContains: "UUID",
		},
		{
			name: "APIBatchBringUpRackRequest - valid ruleId",
			validate: func() error {
				return (&APIBatchBringUpRackRequest{SiteID: "s", RuleID: &validUUID}).Validate()
			},
		},
		// ---- nil vs empty pointer (all types share the same optional-UUID semantics) ----
		{
			name: "APIBringUpRackRequest - nil ruleId is ok",
			validate: func() error {
				return (&APIBringUpRackRequest{SiteID: "s"}).Validate()
			},
		},
		{
			name: "APIBringUpRackRequest - empty-string ruleId is ok (treated as unset)",
			validate: func() error {
				empty := ""
				return (&APIBringUpRackRequest{SiteID: "s", RuleID: &empty}).Validate()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate()
			if tt.wantErr {
				if assert.Error(t, err) && tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}
