// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

// Measurement trust approval types exposed by the REST API.
const (
	MeasurementTrustApprovalTypeOneshot = "Oneshot"
	MeasurementTrustApprovalTypePersist = "Persist"
)

// Selectors supported when deleting a machine trust approval.
const (
	MeasurementTrustedMachineSelectorApprovalID = "ApprovalId"
	MeasurementTrustedMachineSelectorMachineID  = "MachineId"
)

// Selectors supported when deleting a profile trust approval.
const (
	MeasurementTrustedProfileSelectorApprovalID = "ApprovalId"
	MeasurementTrustedProfileSelectorProfileID  = "ProfileId"
)

// APIMeasurementTrustedMachineCreateRequest creates a machine trust approval.
type APIMeasurementTrustedMachineCreateRequest struct {
	SiteID       string `json:"siteId"`
	MachineID    string `json:"machineId"`
	ApprovalType string `json:"approvalType"`
	PCRRegisters string `json:"pcrRegisters,omitempty"`
	Comments     string `json:"comments,omitempty"`
}

// APIMeasurementTrustedProfileCreateRequest creates a profile trust approval.
type APIMeasurementTrustedProfileCreateRequest struct {
	SiteID       string `json:"siteId"`
	ProfileID    string `json:"profileId"`
	ApprovalType string `json:"approvalType"`
	PCRRegisters string `json:"pcrRegisters,omitempty"`
	Comments     string `json:"comments,omitempty"`
}

// APIMeasurementTrustedMachine is a machine trust approval.
type APIMeasurementTrustedMachine struct {
	ApprovalID   string     `json:"approvalId"`
	MachineID    string     `json:"machineId"`
	ApprovalType string     `json:"approvalType"`
	PCRRegisters string     `json:"pcrRegisters,omitempty"`
	Comments     string     `json:"comments,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
}

// APIMeasurementTrustedProfile is a profile trust approval.
type APIMeasurementTrustedProfile struct {
	ApprovalID   string     `json:"approvalId"`
	ProfileID    string     `json:"profileId"`
	ApprovalType string     `json:"approvalType"`
	PCRRegisters string     `json:"pcrRegisters,omitempty"`
	Comments     string     `json:"comments,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
}

// Validate checks a machine trust approval request.
func (r *APIMeasurementTrustedMachineCreateRequest) Validate() error {
	if err := validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error(validationErrorValueRequired), validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&r.MachineID, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&r.ApprovalType, validation.Required.Error(validationErrorValueRequired)),
	); err != nil {
		return err
	}
	if r.MachineID != "*" {
		if err := validation.Validate(r.MachineID, validationis.UUID.Error(validationErrorInvalidUUID)); err != nil {
			return fmt.Errorf("machineId: %w", err)
		}
	}
	return validateMeasurementTrustApprovalType(r.ApprovalType)
}

// Validate checks a profile trust approval request.
func (r *APIMeasurementTrustedProfileCreateRequest) Validate() error {
	if err := validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error(validationErrorValueRequired), validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&r.ProfileID, validation.Required.Error(validationErrorValueRequired), validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&r.ApprovalType, validation.Required.Error(validationErrorValueRequired)),
	); err != nil {
		return err
	}
	return validateMeasurementTrustApprovalType(r.ApprovalType)
}

// ToProto converts a validated machine trust approval request to its Core message.
func (r *APIMeasurementTrustedMachineCreateRequest) ToProto() *corev1.AddMeasurementTrustedMachineRequest {
	return &corev1.AddMeasurementTrustedMachineRequest{
		MachineId:    r.MachineID,
		ApprovalType: measurementTrustApprovalTypeToProto(r.ApprovalType),
		PcrRegisters: r.PCRRegisters,
		Comments:     r.Comments,
	}
}

// ToProto converts a validated profile trust approval request to its Core message.
func (r *APIMeasurementTrustedProfileCreateRequest) ToProto() *corev1.AddMeasurementTrustedProfileRequest {
	req := &corev1.AddMeasurementTrustedProfileRequest{
		ProfileId:    &corev1.MeasurementSystemProfileId{Value: r.ProfileID},
		ApprovalType: measurementTrustApprovalTypeToProto(r.ApprovalType),
	}
	if r.PCRRegisters != "" {
		req.PcrRegisters = &r.PCRRegisters
	}
	if r.Comments != "" {
		req.Comments = &r.Comments
	}
	return req
}

// NewAPIMeasurementTrustedMachine creates an API model from a Core machine trust record.
func NewAPIMeasurementTrustedMachine(record *corev1.MeasurementApprovedMachineRecordPb) *APIMeasurementTrustedMachine {
	if record == nil {
		return nil
	}
	resp := &APIMeasurementTrustedMachine{}
	resp.FromProto(record)
	return resp
}

// FromProto converts one Core machine trust record.
func (r *APIMeasurementTrustedMachine) FromProto(record *corev1.MeasurementApprovedMachineRecordPb) {
	if record == nil {
		return
	}
	*r = APIMeasurementTrustedMachine{
		ApprovalID:   record.GetApprovalId().GetValue(),
		MachineID:    record.GetMachineId(),
		ApprovalType: measurementTrustApprovalTypeFromProto(record.GetApprovalType()),
		PCRRegisters: record.GetPcrRegisters(),
		Comments:     record.GetComments(),
	}
	if ts := record.GetTs(); ts != nil {
		created := ts.AsTime().UTC()
		r.Created = &created
	}
}

// NewAPIMeasurementTrustedProfile creates an API model from a Core profile trust record.
func NewAPIMeasurementTrustedProfile(record *corev1.MeasurementApprovedProfileRecordPb) *APIMeasurementTrustedProfile {
	if record == nil {
		return nil
	}
	resp := &APIMeasurementTrustedProfile{}
	resp.FromProto(record)
	return resp
}

// FromProto converts one Core profile trust record.
func (r *APIMeasurementTrustedProfile) FromProto(record *corev1.MeasurementApprovedProfileRecordPb) {
	if record == nil {
		return
	}
	*r = APIMeasurementTrustedProfile{
		ApprovalID:   record.GetApprovalId().GetValue(),
		ProfileID:    record.GetProfileId().GetValue(),
		ApprovalType: measurementTrustApprovalTypeFromProto(record.GetApprovalType()),
		PCRRegisters: record.GetPcrRegisters(),
		Comments:     record.GetComments(),
	}
	if ts := record.GetTs(); ts != nil {
		created := ts.AsTime().UTC()
		r.Created = &created
	}
}

// APIMeasurementTrustedMachines is a list of machine trust approvals.
type APIMeasurementTrustedMachines []*APIMeasurementTrustedMachine

// FromProto converts Core machine trust records.
func (r *APIMeasurementTrustedMachines) FromProto(records []*corev1.MeasurementApprovedMachineRecordPb) {
	result := make(APIMeasurementTrustedMachines, 0, len(records))
	for _, record := range records {
		result = append(result, NewAPIMeasurementTrustedMachine(record))
	}
	*r = result
}

// APIMeasurementTrustedProfiles is a list of profile trust approvals.
type APIMeasurementTrustedProfiles []*APIMeasurementTrustedProfile

// FromProto converts Core profile trust records.
func (r *APIMeasurementTrustedProfiles) FromProto(records []*corev1.MeasurementApprovedProfileRecordPb) {
	result := make(APIMeasurementTrustedProfiles, 0, len(records))
	for _, record := range records {
		result = append(result, NewAPIMeasurementTrustedProfile(record))
	}
	*r = result
}

// MeasurementTrustedMachineRemoveProto builds and validates a Core machine removal request.
func MeasurementTrustedMachineRemoveProto(selector, id string) (*corev1.RemoveMeasurementTrustedMachineRequest, error) {
	switch selector {
	case MeasurementTrustedMachineSelectorApprovalID:
		if err := validation.Validate(id, validation.Required, validationis.UUID); err != nil {
			return nil, fmt.Errorf("id: %w", err)
		}
		return &corev1.RemoveMeasurementTrustedMachineRequest{
			Selector: &corev1.RemoveMeasurementTrustedMachineRequest_ApprovalId{
				ApprovalId: &corev1.MeasurementApprovedMachineId{Value: id},
			},
		}, nil
	case MeasurementTrustedMachineSelectorMachineID:
		if id != "*" {
			if err := validation.Validate(id, validation.Required, validationis.UUID); err != nil {
				return nil, fmt.Errorf("id: %w", err)
			}
		}
		return &corev1.RemoveMeasurementTrustedMachineRequest{
			Selector: &corev1.RemoveMeasurementTrustedMachineRequest_MachineId{MachineId: id},
		}, nil
	default:
		return nil, fmt.Errorf("invalid selector %q (expected %q or %q)", selector, MeasurementTrustedMachineSelectorApprovalID, MeasurementTrustedMachineSelectorMachineID)
	}
}

// MeasurementTrustedProfileRemoveProto builds and validates a Core profile removal request.
func MeasurementTrustedProfileRemoveProto(selector, id string) (*corev1.RemoveMeasurementTrustedProfileRequest, error) {
	if err := validation.Validate(id, validation.Required, validationis.UUID); err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	switch selector {
	case MeasurementTrustedProfileSelectorApprovalID:
		return &corev1.RemoveMeasurementTrustedProfileRequest{
			Selector: &corev1.RemoveMeasurementTrustedProfileRequest_ApprovalId{
				ApprovalId: &corev1.MeasurementApprovedProfileId{Value: id},
			},
		}, nil
	case MeasurementTrustedProfileSelectorProfileID:
		return &corev1.RemoveMeasurementTrustedProfileRequest{
			Selector: &corev1.RemoveMeasurementTrustedProfileRequest_ProfileId{
				ProfileId: &corev1.MeasurementSystemProfileId{Value: id},
			},
		}, nil
	default:
		return nil, fmt.Errorf("invalid selector %q (expected %q or %q)", selector, MeasurementTrustedProfileSelectorApprovalID, MeasurementTrustedProfileSelectorProfileID)
	}
}

func validateMeasurementTrustApprovalType(approvalType string) error {
	switch approvalType {
	case MeasurementTrustApprovalTypeOneshot, MeasurementTrustApprovalTypePersist:
		return nil
	default:
		return fmt.Errorf("invalid approvalType %q (expected %q or %q)", approvalType, MeasurementTrustApprovalTypeOneshot, MeasurementTrustApprovalTypePersist)
	}
}

func measurementTrustApprovalTypeToProto(approvalType string) corev1.MeasurementApprovedTypePb {
	if approvalType == MeasurementTrustApprovalTypePersist {
		return corev1.MeasurementApprovedTypePb_Persist
	}
	return corev1.MeasurementApprovedTypePb_Oneshot
}

func measurementTrustApprovalTypeFromProto(approvalType corev1.MeasurementApprovedTypePb) string {
	if approvalType == corev1.MeasurementApprovedTypePb_Persist {
		return MeasurementTrustApprovalTypePersist
	}
	return MeasurementTrustApprovalTypeOneshot
}
