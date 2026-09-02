// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationIs "github.com/go-ozzo/ozzo-validation/v4/is"
)

const (
	// SpxAttachmentTypePhysical attaches the SPX Partition over a physical interface
	SpxAttachmentTypePhysical = "Physical"
	// SpxAttachmentTypeVirtual attaches the SPX Partition over a virtual function
	SpxAttachmentTypeVirtual = "Virtual"
	// SpxAttachmentTypeOvn attaches the SPX Partition over OVN
	SpxAttachmentTypeOvn = "Ovn"
)

// APISpxAttachmentCreateRequest is the data structure to capture a user request to attach an SPX Partition to an Instance
type APISpxAttachmentCreateRequest struct {
	// SpxPartitionID is the ID of the SPX Partition
	SpxPartitionID string `json:"spxPartitionId"`
	// Device is the name of the SPX device to use
	Device string `json:"device"`
	// DeviceInstance is the index of the device to use
	DeviceInstance int `json:"deviceInstance"`
	// AttachmentType is the type of SPX attachment: Physical, Virtual, or Ovn
	AttachmentType string `json:"attachmentType"`
	// VirtualFunctionID must be specified if attachmentType is Virtual
	VirtualFunctionID *int `json:"virtualFunctionId"`
}

// Validate ensures the values passed in request are acceptable
func (sacr APISpxAttachmentCreateRequest) Validate() error {
	err := validation.ValidateStruct(&sacr,
		validation.Field(&sacr.SpxPartitionID,
			validation.Required.Error(validationErrorValueRequired),
			validationIs.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&sacr.Device,
			validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&sacr.DeviceInstance,
			validation.Min(0).Error("value must be equal or greater than 0")),
		validation.Field(&sacr.VirtualFunctionID,
			validation.Min(0).Error("value must be equal or greater than 0")),
		validation.Field(&sacr.AttachmentType,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(SpxAttachmentTypePhysical, SpxAttachmentTypeVirtual, SpxAttachmentTypeOvn).Error("must be one of 'Physical', 'Virtual', or 'Ovn'")),
	)
	if err != nil {
		return err
	}

	if sacr.AttachmentType != SpxAttachmentTypeVirtual && sacr.VirtualFunctionID != nil {
		return validation.Errors{
			"virtualFunctionId": errors.New("must only be specified if attachmentType is 'Virtual'"),
		}
	}

	return nil
}
