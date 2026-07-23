// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"time"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
	"google.golang.org/protobuf/proto"
)

// APISku is the data structure to capture API representation of a SKU
type APISku struct {
	// ID is the unique identifier for the SKU
	ID string `json:"id"`
	// SiteID is the ID of the Site this SKU belongs to
	SiteID string `json:"siteId"`
	// DeviceType is the optional device type identifier
	DeviceType *string `json:"deviceType"`
	// AssociatedMachineIds is the list of machine IDs associated with this SKU
	AssociatedMachineIds []string `json:"associatedMachineIds"`
	// Components contains the hardware components of this SKU
	Components *APISkuComponents `json:"components"`
	// Created is the date and time the entity was created
	Created time.Time `json:"created"`
	// Updated is the date and time the entity was last updated
	Updated time.Time `json:"updated"`
}

// APISkuCreateRequest is the POST /sku request body.
type APISkuCreateRequest struct {
	// SiteID is the Site whose Core service will own the SKU.
	SiteID string `json:"siteId"`
	// ID is the unique SKU identifier.
	ID string `json:"id"`
	// Description is the human-readable SKU description.
	Description string `json:"description"`
	// DeviceType is the optional device type identifier.
	DeviceType *string `json:"deviceType,omitempty"`
	// Components is the expected hardware configuration.
	Components *APISkuMutationComponents `json:"components"`
}

// APISkuUpdateRequest is the PATCH /sku/:id request body.
type APISkuUpdateRequest struct {
	// SKUID is populated from the request path before proto conversion.
	SKUID string `json:"-"`
	// Description replaces the description when provided.
	Description *string `json:"description,omitempty"`
	// DeviceType replaces the device type when provided.
	DeviceType *string `json:"deviceType,omitempty"`
	// Components replaces the hardware configuration when provided.
	Components *APISkuMutationComponents `json:"components,omitempty"`
}

// APISkuMutationResponse is the Core-backed representation returned by SKU
// create and update operations. Core does not expose an updated timestamp.
type APISkuMutationResponse struct {
	ID                   string                    `json:"id"`
	SiteID               string                    `json:"siteId"`
	Description          string                    `json:"description"`
	SchemaVersion        uint32                    `json:"schemaVersion"`
	DeviceType           *string                   `json:"deviceType,omitempty"`
	AssociatedMachineIDs []string                  `json:"associatedMachineIds"`
	Components           *APISkuMutationComponents `json:"components"`
	Created              *time.Time                `json:"created,omitempty"`
}

// CoreSkuSchemaVersion is the Core wire format emitted by REST SKU mutations.
const CoreSkuSchemaVersion uint32 = 5

func rejectWritableSkuSchemaVersion(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, found := fields["schemaVersion"]; found {
		return fmt.Errorf("schemaVersion is a read-only SKU field")
	}
	return nil
}

// UnmarshalJSON rejects caller-supplied Core schema versions.
func (r *APISkuCreateRequest) UnmarshalJSON(data []byte) error {
	if err := rejectWritableSkuSchemaVersion(data); err != nil {
		return err
	}

	type skuCreateRequest APISkuCreateRequest
	var decoded skuCreateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = APISkuCreateRequest(decoded)
	return nil
}

// UnmarshalJSON rejects caller-supplied Core schema versions.
func (r *APISkuUpdateRequest) UnmarshalJSON(data []byte) error {
	if err := rejectWritableSkuSchemaVersion(data); err != nil {
		return err
	}

	type skuUpdateRequest APISkuUpdateRequest
	var decoded skuUpdateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = APISkuUpdateRequest(decoded)
	return nil
}

// Validate checks the create request before conversion to Core protobufs.
func (r APISkuCreateRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.SiteID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&r.ID, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&r.Components, validation.Required.Error(validationErrorValueRequired)),
	)
}

// ToProto converts a validated create request into Core's single-item SkuList.
func (r APISkuCreateRequest) ToProto() *corev1.SkuList {
	return &corev1.SkuList{Skus: []*corev1.Sku{{
		Id:            r.ID,
		Description:   &r.Description,
		SchemaVersion: CoreSkuSchemaVersion,
		DeviceType:    r.DeviceType,
		Components:    r.Components.ToProto(),
	}}}
}

// Validate checks the update request and requires at least one mutable field.
func (r APISkuUpdateRequest) Validate() error {
	return validation.By(r.validateHasMutableField).Validate(r)
}

func (r APISkuUpdateRequest) validateHasMutableField(interface{}) error {
	if r.Description == nil && r.DeviceType == nil && r.Components == nil {
		return validation.Errors{"request": validation.NewError("validation_required", "at least one mutable field is required")}
	}
	return nil
}

// ToMetadataProto converts a validated metadata-only PATCH request.
func (r APISkuUpdateRequest) ToMetadataProto() *corev1.SkuUpdateMetadataRequest {
	return &corev1.SkuUpdateMetadataRequest{
		SkuId:       r.SKUID,
		Description: r.Description,
		DeviceType:  r.DeviceType,
	}
}

// ApplyMetadataToProto merges metadata fields into a copy of the current Core SKU.
func (r APISkuUpdateRequest) ApplyMetadataToProto(current *corev1.Sku) *corev1.Sku {
	updated := proto.Clone(current).(*corev1.Sku)
	updated.Id = r.SKUID
	if r.Description != nil {
		updated.Description = r.Description
	}
	if r.DeviceType != nil {
		updated.DeviceType = r.DeviceType
	}
	return updated
}

// ToReplacementProto converts a component PATCH into Core's current SKU format.
func (r APISkuUpdateRequest) ToReplacementProto(current *corev1.Sku) *corev1.Sku {
	updated := r.ApplyMetadataToProto(current)
	updated.SchemaVersion = CoreSkuSchemaVersion
	if r.Components != nil {
		updated.Components = r.Components.ToProto()
	}
	return updated
}

// NewAPISkuMutationResponse converts a Core SKU into the REST mutation response.
func NewAPISkuMutationResponse(sku *corev1.Sku, siteID string) *APISkuMutationResponse {
	if sku == nil {
		return nil
	}
	response := &APISkuMutationResponse{
		ID:                   sku.Id,
		SiteID:               siteID,
		Description:          sku.GetDescription(),
		SchemaVersion:        sku.SchemaVersion,
		DeviceType:           sku.DeviceType,
		AssociatedMachineIDs: []string{},
		Components:           NewAPISkuMutationComponents(sku.Components),
	}
	for _, machineID := range sku.AssociatedMachineIds {
		if id := machineID.GetId(); id != "" {
			response.AssociatedMachineIDs = append(response.AssociatedMachineIDs, id)
		}
	}
	if sku.Created != nil {
		created := sku.Created.AsTime()
		response.Created = &created
	}
	return response
}

// NewAPISkuMutationResponseFromCreateRequest builds the best-known response
// after Core accepted a create request but the post-create read failed.
func NewAPISkuMutationResponseFromCreateRequest(req APISkuCreateRequest, skuID, siteID string) *APISkuMutationResponse {
	return &APISkuMutationResponse{
		ID:                   skuID,
		SiteID:               siteID,
		Description:          req.Description,
		SchemaVersion:        CoreSkuSchemaVersion,
		DeviceType:           req.DeviceType,
		AssociatedMachineIDs: []string{},
		Components:           req.Components,
	}
}

// NewAPISku accepts a DB layer SKU object and returns an API layer object
func NewAPISku(dbSku *cdbm.SKU) *APISku {
	if dbSku == nil {
		return nil
	}

	apiSku := &APISku{
		ID:                   dbSku.ID,
		SiteID:               dbSku.SiteID.String(),
		DeviceType:           dbSku.DeviceType,
		AssociatedMachineIds: dbSku.AssociatedMachineIds,
		Created:              dbSku.Created,
		Updated:              dbSku.Updated,
	}

	// Map SKU Components if available
	if dbSku.Components != nil && dbSku.Components.SkuComponents != nil {
		apiSku.Components = NewAPISkuComponents(dbSku.Components.SkuComponents)
	}

	return apiSku
}

// APISkuComponents is the data structure to capture API representation of SKU Components
type APISkuComponents struct {
	// Cpus describes CPU components
	Cpus []APISkuCpu `json:"cpus"`
	// Gpus describes GPU components
	Gpus []APISkuGpu `json:"gpus"`
	// Memory describes memory components
	Memory []APISkuMemory `json:"memory"`
	// Storage describes storage components
	Storage []APISkuStorage `json:"storage"`
	// Chassis describes chassis component
	Chassis *APISkuChassis `json:"chassis"`
	// EthernetDevices describes ethernet device components
	EthernetDevices []APISkuEthernetDevice `json:"ethernetDevices"`
	// InfinibandDevices describes infiniband device components
	InfinibandDevices []APISkuInfinibandDevice `json:"infinibandDevices"`
	// Tpm describes TPM components
	Tpm *APISkuTpm `json:"tpm"`
}

// APISkuMutationComponents is the hardware component shape accepted and
// returned by SKU mutation endpoints.
type APISkuMutationComponents struct {
	// Cpus describes CPU components
	Cpus []APISkuCpu `json:"cpus"`
	// Gpus describes GPU components
	Gpus []APISkuGpu `json:"gpus"`
	// Memory describes memory components
	Memory []APISkuMemory `json:"memory"`
	// Storage describes storage components accepted by mutation endpoints
	Storage []APISkuStorageMutation `json:"storage"`
	// Chassis describes chassis component
	Chassis *APISkuChassis `json:"chassis"`
	// EthernetDevices describes ethernet device components
	EthernetDevices []APISkuEthernetDevice `json:"ethernetDevices"`
	// InfinibandDevices describes infiniband device components
	InfinibandDevices []APISkuInfinibandDevice `json:"infinibandDevices"`
	// Tpm describes TPM components
	Tpm *APISkuTpm `json:"tpm"`
}

// APISkuCpu represents a CPU component in the SKU
type APISkuCpu struct {
	// Vendor describes the vendor of the CPU
	Vendor string `json:"vendor"`
	// Model describes the model of the CPU
	Model string `json:"model"`
	// ThreadCount describes the number of threads for the CPU
	ThreadCount uint32 `json:"threadCount"`
	// Count describes the number of CPUs present
	Count uint32 `json:"count"`
}

// APISkuGpu represents a GPU component in the SKU
type APISkuGpu struct {
	// Vendor describes the vendor of the GPU
	Vendor string `json:"vendor"`
	// Model describes the model of the GPU
	Model string `json:"model"`
	// TotalMemory describes the total memory of the GPU
	TotalMemory string `json:"totalMemory"`
	// Count describes the number of GPUs present
	Count uint32 `json:"count"`
}

// APISkuMemory represents a memory component in the SKU
type APISkuMemory struct {
	// CapacityMb describes the capacity in megabytes
	CapacityMb uint32 `json:"capacityMb"`
	// MemoryType describes the type of memory (e.g., DDR4, DDR5)
	MemoryType string `json:"memoryType"`
	// Count describes the number of memory modules present
	Count uint32 `json:"count"`
}

// APISkuStorage represents a storage component in the SKU
type APISkuStorage struct {
	// Vendor is retained for response compatibility.
	//
	// Deprecated: Core returns an empty string and does not use this field for matching.
	Vendor string `json:"vendor"`
	// Model is informational starting with the 2.1 release.
	Model string `json:"model"`
	// CapacityMb is retained for response compatibility.
	//
	// Deprecated: Core returns zero; use MinSizeMb and MaxSizeMb for size constraints.
	CapacityMb uint32 `json:"capacityMb"`
	// Count describes the number of storage devices present
	Count uint32 `json:"count"`
	// MinSizeMb is the inclusive minimum capacity for each storage device.
	MinSizeMb *uint32 `json:"minSizeMb,omitempty"`
	// MaxSizeMb is the inclusive maximum capacity for each storage device.
	MaxSizeMb *uint32 `json:"maxSizeMb,omitempty"`
	// PciPatterns contains regular expressions matched against storage PCI paths.
	PciPatterns []string `json:"pciPatterns,omitempty"`
}

// APISkuStorageMutation represents writable storage constraints in a SKU.
type APISkuStorageMutation struct {
	// Model is informational starting with the 2.1 release.
	Model string `json:"model"`
	// Count describes the number of storage devices present.
	Count uint32 `json:"count"`
	// MinSizeMb is the inclusive minimum capacity for each storage device.
	MinSizeMb *uint32 `json:"minSizeMb,omitempty"`
	// MaxSizeMb is the inclusive maximum capacity for each storage device.
	MaxSizeMb *uint32 `json:"maxSizeMb,omitempty"`
	// PciPatterns contains regular expressions matched against storage PCI paths.
	PciPatterns []string `json:"pciPatterns,omitempty"`
}

// UnmarshalJSON rejects legacy read-only storage fields on mutation requests.
func (s *APISkuStorageMutation) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{"vendor", "capacityMb"} {
		if _, found := fields[field]; found {
			return fmt.Errorf("%s is a deprecated read-only SKU storage field", field)
		}
	}

	type storageMutation APISkuStorageMutation
	var decoded storageMutation
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = APISkuStorageMutation(decoded)
	return nil
}

// APISkuChassis represents the chassis component in the SKU
type APISkuChassis struct {
	// Vendor describes the vendor of the chassis
	Vendor string `json:"vendor"`
	// Model describes the model of the chassis
	Model string `json:"model"`
	// Architecture describes the chassis architecture.
	Architecture string `json:"architecture"`
}

// APISkuEthernetDevice represents an ethernet device component in the SKU
type APISkuEthernetDevice struct {
	// Vendor describes the vendor of the ethernet device
	Vendor string `json:"vendor"`
	// Model describes the model of the ethernet device
	Model string `json:"model"`
	// Count describes the number of ethernet devices present
	Count uint32 `json:"count"`
	// IsConnected reports whether the Ethernet device is connected.
	IsConnected bool `json:"isConnected"`
}

// APISkuInfinibandDevice represents an infiniband device component in the SKU
type APISkuInfinibandDevice struct {
	// Vendor describes the vendor of the infiniband device
	Vendor string `json:"vendor"`
	// Model describes the model of the infiniband device
	Model string `json:"model"`
	// Count describes the number of infiniband devices present
	Count uint32 `json:"count"`
	// InactiveDevices contains zero-based indexes of inactive devices.
	InactiveDevices []uint32 `json:"inactiveDevices"`
}

// APISkuTpm represents a TPM component in the SKU
type APISkuTpm struct {
	// Vendor describes the vendor of the TPM
	Vendor string `json:"vendor"`
	// Version describes the version of the TPM
	Version string `json:"version"`
}

// NewAPISkuComponents converts proto SkuComponents to API SkuComponents
func NewAPISkuComponents(protoComponents *corev1.SkuComponents) *APISkuComponents {
	if protoComponents == nil {
		return nil
	}

	apiComponents := &APISkuComponents{}

	// Map CPU components
	if len(protoComponents.Cpus) > 0 {
		apiComponents.Cpus = []APISkuCpu{}
		for _, cpu := range protoComponents.Cpus {
			apiComponents.Cpus = append(apiComponents.Cpus, APISkuCpu{
				Vendor:      cpu.Vendor,
				Model:       cpu.Model,
				ThreadCount: cpu.ThreadCount,
				Count:       cpu.Count,
			})
		}
	}

	// Map GPU components
	if len(protoComponents.Gpus) > 0 {
		apiComponents.Gpus = []APISkuGpu{}
		for _, gpu := range protoComponents.Gpus {
			apiComponents.Gpus = append(apiComponents.Gpus, APISkuGpu{
				Vendor:      gpu.Vendor,
				Model:       gpu.Model,
				TotalMemory: gpu.TotalMemory,
				Count:       gpu.Count,
			})
		}
	}

	// Map Memory components
	if len(protoComponents.Memory) > 0 {
		apiComponents.Memory = []APISkuMemory{}
		for _, mem := range protoComponents.Memory {
			apiComponents.Memory = append(apiComponents.Memory, APISkuMemory{
				CapacityMb: mem.CapacityMb,
				MemoryType: mem.MemoryType,
				Count:      mem.Count,
			})
		}
	}

	// Map Storage components
	if len(protoComponents.Storage) > 0 {
		apiComponents.Storage = []APISkuStorage{}
		for _, storage := range protoComponents.Storage {
			apiComponents.Storage = append(apiComponents.Storage, APISkuStorage{
				Vendor:      storage.Vendor,
				Model:       storage.Model,
				CapacityMb:  storage.CapacityMb,
				Count:       storage.Count,
				MinSizeMb:   storage.MinSizeMb,
				MaxSizeMb:   storage.MaxSizeMb,
				PciPatterns: storage.PciPatterns,
			})
		}
	}

	// Map Chassis component (single object)
	if protoComponents.Chassis != nil {
		apiComponents.Chassis = &APISkuChassis{
			Vendor:       protoComponents.Chassis.Vendor,
			Model:        protoComponents.Chassis.Model,
			Architecture: protoComponents.Chassis.Architecture,
		}
	}

	// Map EthernetDevices components
	if len(protoComponents.EthernetDevices) > 0 {
		apiComponents.EthernetDevices = []APISkuEthernetDevice{}
		for _, ethDev := range protoComponents.EthernetDevices {
			apiComponents.EthernetDevices = append(apiComponents.EthernetDevices, APISkuEthernetDevice{
				Vendor:      ethDev.Vendor,
				Model:       ethDev.Model,
				Count:       ethDev.Count,
				IsConnected: ethDev.IsConnected,
			})
		}
	}

	// Map InfinibandDevices components
	if len(protoComponents.InfinibandDevices) > 0 {
		apiComponents.InfinibandDevices = []APISkuInfinibandDevice{}
		for _, ibDev := range protoComponents.InfinibandDevices {
			apiComponents.InfinibandDevices = append(apiComponents.InfinibandDevices, APISkuInfinibandDevice{
				Vendor:          ibDev.Vendor,
				Model:           ibDev.Model,
				Count:           ibDev.Count,
				InactiveDevices: ibDev.InactiveDevices,
			})
		}
	}

	// Map Tpm components
	if protoComponents.Tpm != nil {
		apiComponents.Tpm = &APISkuTpm{
			Vendor:  protoComponents.Tpm.Vendor,
			Version: protoComponents.Tpm.Version,
		}
	}

	return apiComponents
}

// NewAPISkuMutationComponents converts proto SkuComponents to the mutation API shape.
func NewAPISkuMutationComponents(protoComponents *corev1.SkuComponents) *APISkuMutationComponents {
	if protoComponents == nil {
		return nil
	}

	apiComponents := &APISkuMutationComponents{}
	for _, cpu := range protoComponents.Cpus {
		apiComponents.Cpus = append(apiComponents.Cpus, APISkuCpu{
			Vendor: cpu.Vendor, Model: cpu.Model, ThreadCount: cpu.ThreadCount, Count: cpu.Count,
		})
	}
	for _, gpu := range protoComponents.Gpus {
		apiComponents.Gpus = append(apiComponents.Gpus, APISkuGpu{
			Vendor: gpu.Vendor, Model: gpu.Model, TotalMemory: gpu.TotalMemory, Count: gpu.Count,
		})
	}
	for _, memory := range protoComponents.Memory {
		apiComponents.Memory = append(apiComponents.Memory, APISkuMemory{
			CapacityMb: memory.CapacityMb, MemoryType: memory.MemoryType, Count: memory.Count,
		})
	}
	for _, storage := range protoComponents.Storage {
		apiComponents.Storage = append(apiComponents.Storage, APISkuStorageMutation{
			Model:       storage.Model,
			Count:       storage.Count,
			MinSizeMb:   storage.MinSizeMb,
			MaxSizeMb:   storage.MaxSizeMb,
			PciPatterns: storage.PciPatterns,
		})
	}
	if protoComponents.Chassis != nil {
		apiComponents.Chassis = &APISkuChassis{
			Vendor: protoComponents.Chassis.Vendor, Model: protoComponents.Chassis.Model,
			Architecture: protoComponents.Chassis.Architecture,
		}
	}
	for _, ethernet := range protoComponents.EthernetDevices {
		apiComponents.EthernetDevices = append(apiComponents.EthernetDevices, APISkuEthernetDevice{
			Vendor: ethernet.Vendor, Model: ethernet.Model, Count: ethernet.Count,
			IsConnected: ethernet.IsConnected,
		})
	}
	for _, infiniband := range protoComponents.InfinibandDevices {
		apiComponents.InfinibandDevices = append(apiComponents.InfinibandDevices, APISkuInfinibandDevice{
			Vendor: infiniband.Vendor, Model: infiniband.Model, Count: infiniband.Count,
			InactiveDevices: infiniband.InactiveDevices,
		})
	}
	if protoComponents.Tpm != nil {
		apiComponents.Tpm = &APISkuTpm{
			Vendor: protoComponents.Tpm.Vendor, Version: protoComponents.Tpm.Version,
		}
	}
	return apiComponents
}

// ToProto converts REST SKU components into the Core protobuf shape.
func (c *APISkuComponents) ToProto() *corev1.SkuComponents {
	if c == nil {
		return nil
	}
	components := &corev1.SkuComponents{}
	if c.Chassis != nil {
		components.Chassis = &corev1.SkuComponentChassis{
			Vendor: c.Chassis.Vendor, Model: c.Chassis.Model, Architecture: c.Chassis.Architecture,
		}
	}
	for _, cpu := range c.Cpus {
		components.Cpus = append(components.Cpus, &corev1.SkuComponentCpu{
			Vendor: cpu.Vendor, Model: cpu.Model, ThreadCount: cpu.ThreadCount, Count: cpu.Count,
		})
	}
	for _, gpu := range c.Gpus {
		components.Gpus = append(components.Gpus, &corev1.SkuComponentGpu{
			Vendor: gpu.Vendor, Model: gpu.Model, TotalMemory: gpu.TotalMemory, Count: gpu.Count,
		})
	}
	for _, memory := range c.Memory {
		components.Memory = append(components.Memory, &corev1.SkuComponentMemory{
			CapacityMb: memory.CapacityMb, MemoryType: memory.MemoryType, Count: memory.Count,
		})
	}
	for _, storage := range c.Storage {
		components.Storage = append(components.Storage, &corev1.SkuComponentStorage{
			Vendor: storage.Vendor, Model: storage.Model, CapacityMb: storage.CapacityMb, Count: storage.Count,
			MinSizeMb: storage.MinSizeMb, MaxSizeMb: storage.MaxSizeMb, PciPatterns: storage.PciPatterns,
		})
	}
	for _, ethernet := range c.EthernetDevices {
		components.EthernetDevices = append(components.EthernetDevices, &corev1.SkuComponentEthernetDevices{
			Vendor: ethernet.Vendor, Model: ethernet.Model, Count: ethernet.Count, IsConnected: ethernet.IsConnected,
		})
	}
	for _, infiniband := range c.InfinibandDevices {
		components.InfinibandDevices = append(components.InfinibandDevices, &corev1.SkuComponentInfinibandDevices{
			Vendor: infiniband.Vendor, Model: infiniband.Model, Count: infiniband.Count, InactiveDevices: infiniband.InactiveDevices,
		})
	}
	if c.Tpm != nil {
		components.Tpm = &corev1.SkuComponentTpm{Vendor: c.Tpm.Vendor, Version: c.Tpm.Version}
	}
	return components
}

// ToProto converts REST SKU mutation components into the Core protobuf shape.
func (c *APISkuMutationComponents) ToProto() *corev1.SkuComponents {
	if c == nil {
		return nil
	}
	components := &corev1.SkuComponents{}
	if c.Chassis != nil {
		components.Chassis = &corev1.SkuComponentChassis{
			Vendor: c.Chassis.Vendor, Model: c.Chassis.Model, Architecture: c.Chassis.Architecture,
		}
	}
	for _, cpu := range c.Cpus {
		components.Cpus = append(components.Cpus, &corev1.SkuComponentCpu{
			Vendor: cpu.Vendor, Model: cpu.Model, ThreadCount: cpu.ThreadCount, Count: cpu.Count,
		})
	}
	for _, gpu := range c.Gpus {
		components.Gpus = append(components.Gpus, &corev1.SkuComponentGpu{
			Vendor: gpu.Vendor, Model: gpu.Model, TotalMemory: gpu.TotalMemory, Count: gpu.Count,
		})
	}
	for _, memory := range c.Memory {
		components.Memory = append(components.Memory, &corev1.SkuComponentMemory{
			CapacityMb: memory.CapacityMb, MemoryType: memory.MemoryType, Count: memory.Count,
		})
	}
	for _, storage := range c.Storage {
		components.Storage = append(components.Storage, &corev1.SkuComponentStorage{
			Model: storage.Model, Count: storage.Count, MinSizeMb: storage.MinSizeMb,
			MaxSizeMb: storage.MaxSizeMb, PciPatterns: storage.PciPatterns,
		})
	}
	for _, ethernet := range c.EthernetDevices {
		components.EthernetDevices = append(components.EthernetDevices, &corev1.SkuComponentEthernetDevices{
			Vendor: ethernet.Vendor, Model: ethernet.Model, Count: ethernet.Count, IsConnected: ethernet.IsConnected,
		})
	}
	for _, infiniband := range c.InfinibandDevices {
		components.InfinibandDevices = append(components.InfinibandDevices, &corev1.SkuComponentInfinibandDevices{
			Vendor: infiniband.Vendor, Model: infiniband.Model, Count: infiniband.Count,
			InactiveDevices: infiniband.InactiveDevices,
		})
	}
	if c.Tpm != nil {
		components.Tpm = &corev1.SkuComponentTpm{Vendor: c.Tpm.Vendor, Version: c.Tpm.Version}
	}
	return components
}

// APISkuSummary is the data structure to capture summary of a SKU
type APISkuSummary struct {
	// ID is the unique identifier for the SKU
	ID string `json:"id"`
	// SiteID is the ID of the Site this SKU belongs to
	SiteID string `json:"siteId"`
	// DeviceType is the optional device type identifier
	DeviceType *string `json:"deviceType"`
}

// NewAPISkuSummary accepts a DB layer SKU object and returns an API layer summary object
func NewAPISkuSummary(dbSku *cdbm.SKU) *APISkuSummary {
	if dbSku == nil {
		return nil
	}

	return &APISkuSummary{
		ID:         dbSku.ID,
		SiteID:     dbSku.SiteID.String(),
		DeviceType: dbSku.DeviceType,
	}
}
