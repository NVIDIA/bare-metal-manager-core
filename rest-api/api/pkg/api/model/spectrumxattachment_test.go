// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPISpectrumXAttachmentCreateRequest_Validate(t *testing.T) {
	type fields struct {
		spectrumXPartitionID string
		device               string
		deviceInstance       int
		attachmentType       string
		virtualFunctionID    *int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test validation success, Physical attachment",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       0,
				attachmentType:       SpectrumXAttachmentTypePhysical,
			},
			wantErr: false,
		},
		{
			name: "test validation success, Virtual attachment with virtualFunctionId",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       3,
				attachmentType:       SpectrumXAttachmentTypeVirtual,
				virtualFunctionID:    cutil.GetPtr(2),
			},
			wantErr: false,
		},
		{
			name: "test validation success, Virtual attachment without virtualFunctionId",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       3,
				attachmentType:       SpectrumXAttachmentTypeVirtual,
			},
			wantErr: false,
		},
		{
			name: "test validation success, Ovn attachment",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       0,
				attachmentType:       SpectrumXAttachmentTypeOvn,
			},
			wantErr: false,
		},
		{
			name: "test validation failure, invalid SpectrumX Partition ID",
			fields: fields{
				spectrumXPartitionID: "badid",
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       0,
				attachmentType:       SpectrumXAttachmentTypePhysical,
			},
			wantErr: true,
		},
		{
			name: "test validation failure, missing device",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				deviceInstance:       0,
				attachmentType:       SpectrumXAttachmentTypePhysical,
			},
			wantErr: true,
		},
		{
			name: "test validation failure, invalid attachmentType",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       0,
				attachmentType:       "Bogus",
			},
			wantErr: true,
		},
		{
			name: "test validation failure, virtualFunctionId set for Physical attachment",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       0,
				attachmentType:       SpectrumXAttachmentTypePhysical,
				virtualFunctionID:    cutil.GetPtr(2),
			},
			wantErr: true,
		},
		{
			name: "test validation failure, negative virtualFunctionId",
			fields: fields{
				spectrumXPartitionID: uuid.New().String(),
				device:               "MT2910 Family [ConnectX-7]",
				deviceInstance:       3,
				attachmentType:       SpectrumXAttachmentTypeVirtual,
				virtualFunctionID:    cutil.GetPtr(-1),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sacr := APISpectrumXAttachmentCreateRequest{
				SpectrumXPartitionID: tt.fields.spectrumXPartitionID,
				Device:               tt.fields.device,
				DeviceInstance:       tt.fields.deviceInstance,
				AttachmentType:       tt.fields.attachmentType,
				VirtualFunctionID:    tt.fields.virtualFunctionID,
			}
			err := sacr.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
