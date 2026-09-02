// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

func TestAPIDomainCreateRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request APIDomainCreateRequest
		wantErr bool
	}{
		{
			name:    "valid",
			request: APIDomainCreateRequest{Name: "tenant.example.com", SiteID: uuid.NewString()},
		},
		{
			name:    "missing name",
			request: APIDomainCreateRequest{SiteID: uuid.NewString()},
			wantErr: true,
		},
		{
			name:    "missing site ID",
			request: APIDomainCreateRequest{Name: "tenant.example.com"},
			wantErr: true,
		},
		{
			name:    "invalid site ID",
			request: APIDomainCreateRequest{Name: "tenant.example.com", SiteID: "not-a-uuid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestAPIDomainCreateRequestToProto(t *testing.T) {
	request := APIDomainCreateRequest{Name: "tenant.example.com", SiteID: uuid.NewString()}

	assert.Equal(t, request.Name, request.ToProto().GetName())
}

func TestNewAPIDomainUsesRESTLocalID(t *testing.T) {
	localID := uuid.New()
	controllerID := uuid.New()
	siteID := uuid.New()
	created := time.Now().UTC().Round(time.Microsecond)
	domain := &cdbm.Domain{
		ID:                 localID,
		Hostname:           "tenant.example.com",
		SiteID:             &siteID,
		ControllerDomainID: &controllerID,
		Created:            created,
		Updated:            created,
	}

	got := NewAPIDomain(domain)

	require.NotNil(t, got)
	assert.Equal(t, localID.String(), got.ID)
	assert.NotEqual(t, controllerID.String(), got.ID)
	assert.Equal(t, siteID.String(), got.SiteID)
	assert.Equal(t, domain.Hostname, got.Name)
	assert.Equal(t, created, got.Created)
	assert.Equal(t, created, got.Updated)
}
