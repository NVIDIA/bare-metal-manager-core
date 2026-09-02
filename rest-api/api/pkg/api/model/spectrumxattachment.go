// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationIs "github.com/go-ozzo/ozzo-validation/v4/is"
)

const (
	// SpectrumXAttachmentTypePhysical attaches the SpectrumX Partition over a physical interface
	SpectrumXAttachmentTypePhysical = "Physical"
	// SpectrumXAttachmentTypeVirtual attaches the SpectrumX Partition over a virtual function
	SpectrumXAttachmentTypeVirtual = "Virtual"
	// SpectrumXAttachmentTypeOvn attaches the SpectrumX Partition over OVN
	SpectrumXAttachmentTypeOvn = "Ovn"
)

// APISpectrumXAttachmentCreateRequest is the data structure to capture a user request to attach a SpectrumX Partition to an Instance
type APISpectrumXAttachmentCreateRequest struct {
	// SpectrumXPartitionID is the ID of the SpectrumX Partition
	SpectrumXPartitionID string `json:"spectrumXPartitionId"`
	// Device is the name of the SpectrumX device to use
	Device string `json:"device"`
	// DeviceInstance is the index of the device to use
	DeviceInstance int `json:"deviceInstance"`
	// AttachmentType is the type of SpectrumX attachment: Physical, Virtual, or Ovn
	AttachmentType string `json:"attachmentType"`
	// VirtualFunctionID must be specified if attachmentType is Virtual
	VirtualFunctionID *int `json:"virtualFunctionId"`
}

// Validate ensures the values passed in request are acceptable
func (sacr APISpectrumXAttachmentCreateRequest) Validate() error {
	err := validation.ValidateStruct(&sacr,
		validation.Field(&sacr.SpectrumXPartitionID,
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
			validation.In(SpectrumXAttachmentTypePhysical, SpectrumXAttachmentTypeVirtual, SpectrumXAttachmentTypeOvn).Error("must be one of 'Physical', 'Virtual', or 'Ovn'")),
	)
	if err != nil {
		return err
	}

	if sacr.AttachmentType != SpectrumXAttachmentTypeVirtual && sacr.VirtualFunctionID != nil {
		return validation.Errors{
			"virtualFunctionId": errors.New("must only be specified if attachmentType is 'Virtual'"),
		}
	}

	return nil
}
