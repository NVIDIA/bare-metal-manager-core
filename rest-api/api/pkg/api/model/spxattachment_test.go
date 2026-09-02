// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPISpxAttachmentCreateRequest_Validate(t *testing.T) {
	type fields struct {
		spxPartitionID    string
		device            string
		deviceInstance    int
		attachmentType    string
		virtualFunctionID *int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test validation success, Physical attachment",
			fields: fields{
				spxPartitionID: uuid.New().String(),
				device:         "MT2910 Family [ConnectX-7]",
				deviceInstance: 0,
				attachmentType: SpxAttachmentTypePhysical,
			},
			wantErr: false,
		},
		{
			name: "test validation success, Virtual attachment with virtualFunctionId",
			fields: fields{
				spxPartitionID:    uuid.New().String(),
				device:            "MT2910 Family [ConnectX-7]",
				deviceInstance:    3,
				attachmentType:    SpxAttachmentTypeVirtual,
				virtualFunctionID: cutil.GetPtr(2),
			},
			wantErr: false,
		},
		{
			name: "test validation success, Virtual attachment without virtualFunctionId",
			fields: fields{
				spxPartitionID: uuid.New().String(),
				device:         "MT2910 Family [ConnectX-7]",
				deviceInstance: 3,
				attachmentType: SpxAttachmentTypeVirtual,
			},
			wantErr: false,
		},
		{
			name: "test validation success, Ovn attachment",
			fields: fields{
				spxPartitionID: uuid.New().String(),
				device:         "MT2910 Family [ConnectX-7]",
				deviceInstance: 0,
				attachmentType: SpxAttachmentTypeOvn,
			},
			wantErr: false,
		},
		{
			name: "test validation failure, invalid SPX Partition ID",
			fields: fields{
				spxPartitionID: "badid",
				device:         "MT2910 Family [ConnectX-7]",
				deviceInstance: 0,
				attachmentType: SpxAttachmentTypePhysical,
			},
			wantErr: true,
		},
		{
			name: "test validation failure, missing device",
			fields: fields{
				spxPartitionID: uuid.New().String(),
				deviceInstance: 0,
				attachmentType: SpxAttachmentTypePhysical,
			},
			wantErr: true,
		},
		{
			name: "test validation failure, invalid attachmentType",
			fields: fields{
				spxPartitionID: uuid.New().String(),
				device:         "MT2910 Family [ConnectX-7]",
				deviceInstance: 0,
				attachmentType: "Bogus",
			},
			wantErr: true,
		},
		{
			name: "test validation failure, virtualFunctionId set for Physical attachment",
			fields: fields{
				spxPartitionID:    uuid.New().String(),
				device:            "MT2910 Family [ConnectX-7]",
				deviceInstance:    0,
				attachmentType:    SpxAttachmentTypePhysical,
				virtualFunctionID: cutil.GetPtr(2),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sacr := APISpxAttachmentCreateRequest{
				SpxPartitionID:    tt.fields.spxPartitionID,
				Device:            tt.fields.device,
				DeviceInstance:    tt.fields.deviceInstance,
				AttachmentType:    tt.fields.attachmentType,
				VirtualFunctionID: tt.fields.virtualFunctionID,
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
