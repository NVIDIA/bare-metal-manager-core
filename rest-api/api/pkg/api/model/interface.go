// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"net/netip"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
)

// APIInterfaceCreateRequest is the data structure to capture user request to create a new Interface
type APIInterfaceCreateOrUpdateRequest struct {
	// SubnetID is the ID of the Subnet
	SubnetID *string `json:"subnetId"`
	// VpcPrefixID is the ID of the VpcPrefix
	VpcPrefixID *string `json:"vpcPrefixId"`
	// IPAddress is the explicitly requested IP address for the Interface
	IPAddress *string `json:"ipAddress"`
	// Device is the device name of the Interface
	Device *string `json:"device"`
	// DeviceInstance is the ID of the DeviceInstance
	DeviceInstance *int `json:"deviceInstance"`
	// VirtualFunctionID is the ID of the Virtual Function
	VirtualFunctionID *int `json:"virtualFunctionId"`
	// IsPhysical indicates whether the Subnet is bound on a physical Interface
	IsPhysical bool `json:"isPhysical"`
}

func (ifcr APIInterfaceCreateOrUpdateRequest) IsMultiEthernetInterface() bool {
	return ifcr.Device != nil && ifcr.DeviceInstance != nil
}

func validateInterfaceRequestedIpAddressHostBit(value any) error {
	ipStr, ok := value.(*string)
	if !ok || ipStr == nil {
		return nil
	}

	addr, err := netip.ParseAddr(*ipStr)
	if err != nil {
		return errors.New("ipAddress must be a valid IPv4 or IPv6 address")
	}

	ipBytes := addr.AsSlice()
	if len(ipBytes) == 0 || ipBytes[len(ipBytes)-1]&0x01 == 0 {
		return errors.New("ipAddress must have a final host bit of 1")
	}

	return nil
}

// Validate ensure the values passed in request are acceptable
func (ifcr APIInterfaceCreateOrUpdateRequest) Validate() error {
	err := validation.ValidateStruct(&ifcr,
		validation.Field(&ifcr.SubnetID,
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&ifcr.VpcPrefixID,
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&ifcr.IPAddress,
			validation.When(ifcr.IPAddress != nil, validation.By(validateInterfaceRequestedIpAddressHostBit)),
		),
		validation.Field(&ifcr.DeviceInstance,
			validation.Min(0).Error("deviceInstance must be equal or greater than 0")),
		validation.Field(&ifcr.VirtualFunctionID,
			validation.Min(1).Error("virtualFunctionId must be between 1 and 16"),
			validation.Max(16).Error("virtualFunctionId must be between 1 and 16")),
	)

	if ifcr.SubnetID != nil && ifcr.VpcPrefixID != nil {
		return validation.Errors{
			"subnetId": errors.New("`subnetId` and `vpcPrefixId` cannot be specified together"),
		}
	}

	if ifcr.IPAddress != nil && ifcr.SubnetID != nil {
		return validation.Errors{
			"ipAddress": errors.New("cannot be specified for Subnet based Interfaces"),
		}
	}

	if ifcr.SubnetID == nil && ifcr.VpcPrefixID == nil {
		return validation.Errors{
			validationCommonErrorField: errors.New("either `subnetId` or `vpcPrefixId` must be specified"),
		}
	}

	if ifcr.Device != nil {
		if ifcr.DeviceInstance == nil {
			return validation.Errors{
				"deviceInstance": errors.New("must be specified when `device` is specified"),
			}
		}

		if ifcr.VpcPrefixID == nil {
			return validation.Errors{
				"vpcPrefixId": errors.New("must be specified when `device` and `deviceInstance` are specified"),
			}
		}

		// virtualFunctionId is required when Device/DeviceInstance is present and isPhysical is false
		if !ifcr.IsPhysical && ifcr.VirtualFunctionID == nil {
			return validation.Errors{
				"virtualFunctionId": errors.New("must be specified when `device` and `deviceInstance` are specified and `isPhysical` is false"),
			}
		}
	} else if ifcr.DeviceInstance != nil {
		return validation.Errors{
			"device": errors.New("must be specified when `deviceInstance` is specified"),
		}
	}

	return err
}

// APIInterface is the data structure to capture Interface
type APIInterface struct {
	// ID is the unique UUID v4 identifier for the Interface
	ID string `json:"id"`
	// InstanceID is the ID of the associated Instance
	InstanceID string `json:"instanceId"`
	// Instance is the summary of the Instance
	Instance *APIInstanceSummary `json:"instance,omitempty"`
	// SubnetID is the ID of the associated Subnet
	SubnetID *string `json:"subnetId"`
	// Subnet is the summary of the Subnet
	Subnet *APISubnetSummary `json:"subnet,omitempty"`
	// VpcPrefixID is the ID of the associated VpcPrefix
	VpcPrefixID *string `json:"vpcPrefixId"`
	// VpcPrefix is the summary of the VpcPrefix
	VpcPrefix *APIVpcPrefixSummary `json:"vpcprefix,omitempty"`
	// Device is the device name of the Interface
	Device *string `json:"device"`
	// DeviceInstance is the ID of the DeviceInstance
	DeviceInstance *int `json:"deviceInstance"`
	// VirtualFunctionID is the ID of the Virtual Function
	VirtualFunctionID *int `json:"virtualFunctionId"`
	// IsPhysical indicates whether the Subnet is bound on a physical Interface
	IsPhysical bool `json:"isPhysical"`
	// MacAddress is the MAC address of the Interface
	MacAddress *string `json:"macAddress"`
	// IPAddresses is the list of IP addresses assigned to the Interface
	IPAddresses []string `json:"ipAddresses"`
	// RequestedIpAddress is the explicitly requested IP address for the Interface
	RequestedIpAddress *string `json:"requestedIpAddress"`
	// Status is the status of the Interface
	Status string `json:"status"`
	// Created is the date and time the entity was created
	Created time.Time `json:"created"`
	// Updated is the date and time the entity was last updated
	Updated time.Time `json:"updated"`
}

// NewAPIInterface creates a new APIInterface
func NewAPIInterface(dbis *cdbm.Interface) *APIInterface {
	apiInterface := &APIInterface{
		ID:                 dbis.ID.String(),
		InstanceID:         dbis.InstanceID.String(),
		IsPhysical:         dbis.IsPhysical,
		MacAddress:         dbis.MacAddress,
		IPAddresses:        dbis.IPAddresses,
		RequestedIpAddress: dbis.RequestedIpAddress,
		Status:             dbis.Status,
		Created:            dbis.Created,
		Updated:            dbis.Updated,
	}

	if dbis.Instance != nil {
		apiInterface.Instance = NewAPIInstanceSummary(dbis.Instance)
	}

	if dbis.SubnetID != nil {
		apiInterface.SubnetID = cdb.GetStrPtr(dbis.SubnetID.String())
	}

	if dbis.Subnet != nil {
		apiInterface.Subnet = NewAPISubnetSummary(dbis.Subnet)
	}

	if dbis.VpcPrefixID != nil {
		apiInterface.VpcPrefixID = cdb.GetStrPtr(dbis.VpcPrefixID.String())
	}

	if dbis.VpcPrefix != nil {
		apiInterface.VpcPrefix = NewAPIVpcPrefixSummary(dbis.VpcPrefix)
	}

	if dbis.Device != nil {
		apiInterface.Device = dbis.Device
	}

	if dbis.DeviceInstance != nil {
		apiInterface.DeviceInstance = dbis.DeviceInstance
	}

	if dbis.VirtualFunctionID != nil {
		apiInterface.VirtualFunctionID = dbis.VirtualFunctionID
	}

	return apiInterface
}
