// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
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
	// Vendor describes the vendor of the storage device
	Vendor string `json:"vendor"`
	// Model describes the model of the storage device
	Model string `json:"model"`
	// CapacityMb describes the capacity in megabytes
	CapacityMb uint32 `json:"capacityMb"`
	// Count describes the number of storage devices present
	Count uint32 `json:"count"`
}

// APISkuChassis represents the chassis component in the SKU
type APISkuChassis struct {
	// Vendor describes the vendor of the chassis
	Vendor string `json:"vendor"`
	// Model describes the model of the chassis
	Model string `json:"model"`
}

// APISkuEthernetDevice represents an ethernet device component in the SKU
type APISkuEthernetDevice struct {
	// Vendor describes the vendor of the ethernet device
	Vendor string `json:"vendor"`
	// Model describes the model of the ethernet device
	Model string `json:"model"`
	// Count describes the number of ethernet devices present
	Count uint32 `json:"count"`
}

// APISkuInfinibandDevice represents an infiniband device component in the SKU
type APISkuInfinibandDevice struct {
	// Vendor describes the vendor of the infiniband device
	Vendor string `json:"vendor"`
	// Model describes the model of the infiniband device
	Model string `json:"model"`
	// Count describes the number of infiniband devices present
	Count uint32 `json:"count"`
}

// APISkuTpm represents a TPM component in the SKU
type APISkuTpm struct {
	// Vendor describes the vendor of the TPM
	Vendor string `json:"vendor"`
	// Version describes the version of the TPM
	Version string `json:"version"`
}

// NewAPISkuComponents converts proto SkuComponents to API SkuComponents
func NewAPISkuComponents(protoComponents *cwssaws.SkuComponents) *APISkuComponents {
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
				Vendor:     storage.Vendor,
				Model:      storage.Model,
				CapacityMb: storage.CapacityMb,
				Count:      storage.Count,
			})
		}
	}

	// Map Chassis component (single object)
	if protoComponents.Chassis != nil {
		apiComponents.Chassis = &APISkuChassis{
			Vendor: protoComponents.Chassis.Vendor,
			Model:  protoComponents.Chassis.Model,
		}
	}

	// Map EthernetDevices components
	if len(protoComponents.EthernetDevices) > 0 {
		apiComponents.EthernetDevices = []APISkuEthernetDevice{}
		for _, ethDev := range protoComponents.EthernetDevices {
			apiComponents.EthernetDevices = append(apiComponents.EthernetDevices, APISkuEthernetDevice{
				Vendor: ethDev.Vendor,
				Model:  ethDev.Model,
				Count:  ethDev.Count,
			})
		}
	}

	// Map InfinibandDevices components
	if len(protoComponents.InfinibandDevices) > 0 {
		apiComponents.InfinibandDevices = []APISkuInfinibandDevice{}
		for _, ibDev := range protoComponents.InfinibandDevices {
			apiComponents.InfinibandDevices = append(apiComponents.InfinibandDevices, APISkuInfinibandDevice{
				Vendor: ibDev.Vendor,
				Model:  ibDev.Model,
				Count:  ibDev.Count,
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
