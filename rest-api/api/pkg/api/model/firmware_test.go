// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
	"github.com/stretchr/testify/assert"
)

func TestAPIUpdateFirmwareRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIUpdateFirmwareRequest
		wantErr bool
	}{
		{
			name:    "valid - with siteId and version",
			request: APIUpdateFirmwareRequest{SiteID: "site-1", Version: strPtr("24.11.0")},
			wantErr: false,
		},
		{
			name:    "valid - with siteId only (no version)",
			request: APIUpdateFirmwareRequest{SiteID: "site-1"},
			wantErr: false,
		},
		{
			name:    "invalid - missing siteId",
			request: APIUpdateFirmwareRequest{Version: strPtr("24.11.0")},
			wantErr: true,
		},
		{
			name: "valid - targets with version",
			request: APIUpdateFirmwareRequest{
				SiteID:  "site-1",
				Version: strPtr("24.11.0"),
				Targets: []string{"bmc", "nvos"},
			},
			wantErr: false,
		},
		{
			name: "invalid - targets without version",
			request: APIUpdateFirmwareRequest{
				SiteID:  "site-1",
				Targets: []string{"bmc"},
			},
			wantErr: true,
		},
		{
			name: "invalid - targets with empty version string",
			request: APIUpdateFirmwareRequest{
				SiteID:  "site-1",
				Version: strPtr(""),
				Targets: []string{"bmc"},
			},
			wantErr: true,
		},
		{
			name: "invalid - targets contains empty string",
			request: APIUpdateFirmwareRequest{
				SiteID:  "site-1",
				Version: strPtr("24.11.0"),
				Targets: []string{"bmc", ""},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPIBatchTrayFirmwareUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIBatchTrayFirmwareUpdateRequest
		wantErr bool
	}{
		{
			name:    "valid - siteId only",
			request: APIBatchTrayFirmwareUpdateRequest{SiteID: "site-1"},
			wantErr: false,
		},
		{
			name: "valid - with filter and version",
			request: APIBatchTrayFirmwareUpdateRequest{
				SiteID:  "site-1",
				Filter:  &TrayFilter{IDs: []string{"550e8400-e29b-41d4-a716-446655440000"}},
				Version: strPtr("24.11.0"),
			},
			wantErr: false,
		},
		{
			name: "valid - targets with version",
			request: APIBatchTrayFirmwareUpdateRequest{
				SiteID:  "site-1",
				Version: strPtr("24.11.0"),
				Targets: []string{"bmc"},
			},
			wantErr: false,
		},
		{
			name: "invalid - targets without version",
			request: APIBatchTrayFirmwareUpdateRequest{
				SiteID:  "site-1",
				Targets: []string{"bmc"},
			},
			wantErr: true,
		},
		{
			name:    "invalid - missing siteId",
			request: APIBatchTrayFirmwareUpdateRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewAPIUpdateFirmwareResponse(t *testing.T) {
	tests := []struct {
		name     string
		resp     *flowv1.SubmitTaskResponse
		expected *APIUpdateFirmwareResponse
	}{
		{
			name:     "nil response returns empty task IDs",
			resp:     nil,
			expected: &APIUpdateFirmwareResponse{TaskIDs: []string{}},
		},
		{
			name: "single task ID",
			resp: &flowv1.SubmitTaskResponse{
				TaskIds: []*flowv1.UUID{{Id: "task-1"}},
			},
			expected: &APIUpdateFirmwareResponse{TaskIDs: []string{"task-1"}},
		},
		{
			name: "multiple task IDs",
			resp: &flowv1.SubmitTaskResponse{
				TaskIds: []*flowv1.UUID{{Id: "task-1"}, {Id: "task-2"}},
			},
			expected: &APIUpdateFirmwareResponse{TaskIDs: []string{"task-1", "task-2"}},
		},
		{
			name:     "empty task IDs",
			resp:     &flowv1.SubmitTaskResponse{},
			expected: &APIUpdateFirmwareResponse{TaskIDs: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewAPIUpdateFirmwareResponse(tt.resp)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAPIBatchRackFirmwareUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request APIBatchRackFirmwareUpdateRequest
		wantErr bool
	}{
		{
			name:    "valid - with siteId only",
			request: APIBatchRackFirmwareUpdateRequest{SiteID: "site-1"},
			wantErr: false,
		},
		{
			name: "valid - with filter and version",
			request: APIBatchRackFirmwareUpdateRequest{
				SiteID:  "site-1",
				Filter:  &RackFilter{Names: []string{"rack-1"}},
				Version: strPtr("1.0"),
			},
			wantErr: false,
		},
		{
			name:    "invalid - missing siteId",
			request: APIBatchRackFirmwareUpdateRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
