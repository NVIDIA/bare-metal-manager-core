// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

func TestMeasurementTrustedMachineCreateRequest(t *testing.T) {
	req := APIMeasurementTrustedMachineCreateRequest{
		SiteID:       "00000000-0000-0000-0000-000000000001",
		MachineID:    "*",
		ApprovalType: MeasurementTrustApprovalTypePersist,
		PCRRegisters: "0,3,5,6",
		Comments:     "trusted fleet",
	}
	require.NoError(t, req.Validate())

	protoReq := req.ToProto()
	assert.Equal(t, "*", protoReq.GetMachineId())
	assert.Equal(t, corev1.MeasurementApprovedTypePb_Persist, protoReq.GetApprovalType())
	assert.Equal(t, "0,3,5,6", protoReq.GetPcrRegisters())
	assert.Equal(t, "trusted fleet", protoReq.GetComments())
}

func TestMeasurementTrustedMachineCreateRequestRejectsInvalidMachine(t *testing.T) {
	req := APIMeasurementTrustedMachineCreateRequest{
		SiteID:       "00000000-0000-0000-0000-000000000001",
		MachineID:    "not-a-machine-id",
		ApprovalType: MeasurementTrustApprovalTypeOneshot,
	}
	assert.ErrorContains(t, req.Validate(), "machineId")
}

func TestMeasurementTrustedProfileCreateRequest(t *testing.T) {
	req := APIMeasurementTrustedProfileCreateRequest{
		SiteID:       "00000000-0000-0000-0000-000000000001",
		ProfileID:    "00000000-0000-0000-0000-000000000002",
		ApprovalType: MeasurementTrustApprovalTypeOneshot,
	}
	require.NoError(t, req.Validate())

	protoReq := req.ToProto()
	assert.Equal(t, req.ProfileID, protoReq.GetProfileId().GetValue())
	assert.Equal(t, corev1.MeasurementApprovedTypePb_Oneshot, protoReq.GetApprovalType())
	assert.Nil(t, protoReq.PcrRegisters)
	assert.Nil(t, protoReq.Comments)
}

func TestMeasurementTrustCreateRequestRejectsInvalidApprovalType(t *testing.T) {
	req := APIMeasurementTrustedMachineCreateRequest{
		SiteID:       "00000000-0000-0000-0000-000000000001",
		MachineID:    "00000000-0000-0000-0000-000000000002",
		ApprovalType: "Forever",
	}
	assert.ErrorContains(t, req.Validate(), "approvalType")
}

func TestMeasurementTrustRemoveProtoSelectors(t *testing.T) {
	id := "00000000-0000-0000-0000-000000000001"

	machineByApproval, err := MeasurementTrustedMachineRemoveProto(MeasurementTrustedMachineSelectorApprovalID, id)
	require.NoError(t, err)
	assert.Equal(t, id, machineByApproval.GetApprovalId().GetValue())

	machineByMachine, err := MeasurementTrustedMachineRemoveProto(MeasurementTrustedMachineSelectorMachineID, id)
	require.NoError(t, err)
	assert.Equal(t, id, machineByMachine.GetMachineId())

	profileByApproval, err := MeasurementTrustedProfileRemoveProto(MeasurementTrustedProfileSelectorApprovalID, id)
	require.NoError(t, err)
	assert.Equal(t, id, profileByApproval.GetApprovalId().GetValue())

	profileByProfile, err := MeasurementTrustedProfileRemoveProto(MeasurementTrustedProfileSelectorProfileID, id)
	require.NoError(t, err)
	assert.Equal(t, id, profileByProfile.GetProfileId().GetValue())

	_, err = MeasurementTrustedMachineRemoveProto("invalid", id)
	assert.ErrorContains(t, err, "invalid selector")
}

func TestMeasurementTrustResponsesFromProto(t *testing.T) {
	created := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	machineRecord := &corev1.MeasurementApprovedMachineRecordPb{
		ApprovalId:   &corev1.MeasurementApprovedMachineId{Value: "00000000-0000-0000-0000-000000000001"},
		MachineId:    "00000000-0000-0000-0000-000000000002",
		ApprovalType: corev1.MeasurementApprovedTypePb_Persist,
		PcrRegisters: "0,7",
		Comments:     "trusted machine",
		Ts:           timestamppb.New(created),
	}
	machine := NewAPIMeasurementTrustedMachine(machineRecord)
	require.NotNil(t, machine)
	assert.Equal(t, MeasurementTrustApprovalTypePersist, machine.ApprovalType)
	assert.Equal(t, created, *machine.Created)

	profileRecord := &corev1.MeasurementApprovedProfileRecordPb{
		ApprovalId:   &corev1.MeasurementApprovedProfileId{Value: "00000000-0000-0000-0000-000000000003"},
		ProfileId:    &corev1.MeasurementSystemProfileId{Value: "00000000-0000-0000-0000-000000000004"},
		ApprovalType: corev1.MeasurementApprovedTypePb_Oneshot,
		Ts:           timestamppb.New(created),
	}
	profile := NewAPIMeasurementTrustedProfile(profileRecord)
	require.NotNil(t, profile)
	assert.Equal(t, MeasurementTrustApprovalTypeOneshot, profile.ApprovalType)
	assert.Equal(t, created, *profile.Created)

	var machines APIMeasurementTrustedMachines
	machines.FromProto([]*corev1.MeasurementApprovedMachineRecordPb{machineRecord, nil})
	require.Len(t, machines, 2)
	assert.Equal(t, machine, machines[0])
	assert.Nil(t, machines[1])

	var profiles APIMeasurementTrustedProfiles
	profiles.FromProto([]*corev1.MeasurementApprovedProfileRecordPb{profileRecord, nil})
	require.Len(t, profiles, 2)
	assert.Equal(t, profile, profiles[0])
	assert.Nil(t, profiles[1])
}
