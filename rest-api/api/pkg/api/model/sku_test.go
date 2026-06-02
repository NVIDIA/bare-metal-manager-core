// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAPISku(t *testing.T) {
	type args struct {
		dbSku *cdbm.SKU
	}

	siteID := uuid.New()
	deviceType := "test-device-type"
	associatedMachineIds := []string{"machine-1", "machine-2"}
	createdTime := time.Now()
	updatedTime := time.Now()

	// Test with full SKU data
	dbSku := &cdbm.SKU{
		ID:                   "test-sku-id",
		SiteID:               siteID,
		DeviceType:           &deviceType,
		AssociatedMachineIds: associatedMachineIds,
		Created:              createdTime,
		Updated:              updatedTime,
	}

	// Test with SKU that has basic components - using minimal structure for testing
	// since proto types may vary across versions

	tests := []struct {
		name string
		args args
		want *APISku
	}{
		{
			name: "test new API SKU with basic data",
			args: args{
				dbSku: dbSku,
			},
			want: &APISku{
				ID:                   dbSku.ID,
				SiteID:               siteID.String(),
				DeviceType:           &deviceType,
				AssociatedMachineIds: associatedMachineIds,
				Created:              createdTime,
				Updated:              updatedTime,
			},
		},
		{
			name: "test new API SKU with nil input",
			args: args{
				dbSku: nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAPISku(tt.args.dbSku)

			// Handle nil cases
			if got == nil && tt.want == nil {
				return
			}
			if (got == nil) != (tt.want == nil) {
				t.Errorf("NewAPISku() = %v, want %v", got, tt.want)
				return
			}

			// Compare basic fields
			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.SiteID, got.SiteID)
			assert.Equal(t, tt.want.DeviceType, got.DeviceType)
			assert.Equal(t, tt.want.AssociatedMachineIds, got.AssociatedMachineIds)
			assert.Equal(t, tt.want.Created, got.Created)
			assert.Equal(t, tt.want.Updated, got.Updated)
		})
	}
}

func TestNewAPISkuComponents(t *testing.T) {
	// Test with nil input
	t.Run("test new API SKU Components with nil input", func(t *testing.T) {
		result := NewAPISkuComponents(nil)
		assert.Nil(t, result)
	})

	// Test with empty input
	t.Run("test new API SKU Components with empty input", func(t *testing.T) {
		result := NewAPISkuComponents(&cwssaws.SkuComponents{})
		assert.NotNil(t, result)
		assert.Nil(t, result.Cpus)
		assert.Nil(t, result.Gpus)
		assert.Nil(t, result.Memory)
		assert.Nil(t, result.Storage)
	})
}

func TestNewAPISkuWithFullComponents(t *testing.T) {
	siteID := uuid.New()
	deviceType := "gpu-server"
	createdTime := time.Now()
	updatedTime := time.Now()

	t.Run("complete GPU server with all component types", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:                   "sku-gpu-server-01",
			SiteID:               siteID,
			DeviceType:           &deviceType,
			AssociatedMachineIds: []string{"machine-001", "machine-002", "machine-003"},
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "Intel",
							Model:       "Xeon Platinum 8480+",
							ThreadCount: 112,
							Count:       2,
						},
					},
					Gpus: []*cwssaws.SkuComponentGpu{
						{
							Vendor:      "NVIDIA",
							Model:       "H100 SXM5",
							TotalMemory: "80GB HBM3",
							Count:       8,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 65536,
							MemoryType: "DDR5",
							Count:      16,
						},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{
							Vendor:     "Samsung",
							Model:      "PM9A3",
							CapacityMb: 7680000,
							Count:      4,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "Supermicro",
						Model:  "SYS-420GP-TNR",
					},
					Tpm: &cwssaws.SkuComponentTpm{
						Vendor:  "Infineon",
						Version: "2.0",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)

		assert.NotNil(t, result)
		assert.Equal(t, "sku-gpu-server-01", result.ID)
		assert.Equal(t, siteID.String(), result.SiteID)
		assert.Equal(t, "gpu-server", *result.DeviceType)
		assert.Equal(t, []string{"machine-001", "machine-002", "machine-003"}, result.AssociatedMachineIds)

		// Validate CPUs
		assert.NotNil(t, result.Components)
		assert.Len(t, result.Components.Cpus, 1)
		assert.Equal(t, "Intel", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "Xeon Platinum 8480+", result.Components.Cpus[0].Model)
		assert.Equal(t, uint32(112), result.Components.Cpus[0].ThreadCount)
		assert.Equal(t, uint32(2), result.Components.Cpus[0].Count)

		// Validate GPUs
		assert.Len(t, result.Components.Gpus, 1)
		assert.Equal(t, "NVIDIA", result.Components.Gpus[0].Vendor)
		assert.Equal(t, "H100 SXM5", result.Components.Gpus[0].Model)
		assert.Equal(t, "80GB HBM3", result.Components.Gpus[0].TotalMemory)
		assert.Equal(t, uint32(8), result.Components.Gpus[0].Count)

		// Validate Memory
		assert.Len(t, result.Components.Memory, 1)
		assert.Equal(t, uint32(65536), result.Components.Memory[0].CapacityMb)
		assert.Equal(t, "DDR5", result.Components.Memory[0].MemoryType)
		assert.Equal(t, uint32(16), result.Components.Memory[0].Count)

		// Validate Storage
		assert.Len(t, result.Components.Storage, 1)
		assert.Equal(t, "Samsung", result.Components.Storage[0].Vendor)
		assert.Equal(t, "PM9A3", result.Components.Storage[0].Model)
		assert.Equal(t, uint32(7680000), result.Components.Storage[0].CapacityMb)
		assert.Equal(t, uint32(4), result.Components.Storage[0].Count)

		// Validate Chassis
		assert.NotNil(t, result.Components.Chassis)
		assert.Equal(t, "Supermicro", result.Components.Chassis.Vendor)
		assert.Equal(t, "SYS-420GP-TNR", result.Components.Chassis.Model)

		// Validate TPM
		assert.NotNil(t, result.Components.Tpm)
		assert.Equal(t, "Infineon", result.Components.Tpm.Vendor)
		assert.Equal(t, "2.0", result.Components.Tpm.Version)
	})

	t.Run("multi-GPU configuration with different GPU types", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:                   "sku-multi-gpu-01",
			SiteID:               siteID,
			DeviceType:           &deviceType,
			AssociatedMachineIds: []string{"machine-010"},
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "AMD",
							Model:       "EPYC 9654",
							ThreadCount: 192,
							Count:       2,
						},
					},
					Gpus: []*cwssaws.SkuComponentGpu{
						{
							Vendor:      "NVIDIA",
							Model:       "A100 80GB",
							TotalMemory: "80GB HBM2e",
							Count:       4,
						},
						{
							Vendor:      "NVIDIA",
							Model:       "H100 PCIe",
							TotalMemory: "80GB HBM3",
							Count:       4,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 32768,
							MemoryType: "DDR5",
							Count:      32,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "Dell",
						Model:  "PowerEdge XE9680",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)

		assert.NotNil(t, result)
		assert.Len(t, result.Components.Gpus, 2)
		assert.Equal(t, "A100 80GB", result.Components.Gpus[0].Model)
		assert.Equal(t, uint32(4), result.Components.Gpus[0].Count)
		assert.Equal(t, "H100 PCIe", result.Components.Gpus[1].Model)
		assert.Equal(t, uint32(4), result.Components.Gpus[1].Count)

		assert.Len(t, result.Components.Cpus, 1)
		assert.Equal(t, "AMD", result.Components.Cpus[0].Vendor)
		assert.Equal(t, uint32(192), result.Components.Cpus[0].ThreadCount)
	})

	t.Run("storage-optimized configuration", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-storage-01",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "Intel",
							Model:       "Xeon Gold 6438N",
							ThreadCount: 64,
							Count:       2,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 65536,
							MemoryType: "DDR5 ECC",
							Count:      8,
						},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{
							Vendor:     "Samsung",
							Model:      "PM1733",
							CapacityMb: 15360000,
							Count:      24,
						},
						{
							Vendor:     "Intel",
							Model:      "P5520",
							CapacityMb: 7680000,
							Count:      4,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "HPE",
						Model:  "ProLiant DL380 Gen11",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)

		assert.NotNil(t, result)
		assert.Len(t, result.Components.Storage, 2)

		// Validate first storage type
		assert.Equal(t, "Samsung", result.Components.Storage[0].Vendor)
		assert.Equal(t, "PM1733", result.Components.Storage[0].Model)
		assert.Equal(t, uint32(15360000), result.Components.Storage[0].CapacityMb)
		assert.Equal(t, uint32(24), result.Components.Storage[0].Count)

		// Validate second storage type
		assert.Equal(t, "Intel", result.Components.Storage[1].Vendor)
		assert.Equal(t, "P5520", result.Components.Storage[1].Model)
		assert.Equal(t, uint32(7680000), result.Components.Storage[1].CapacityMb)
		assert.Equal(t, uint32(4), result.Components.Storage[1].Count)

		// Validate memory configuration
		assert.Len(t, result.Components.Memory, 1)
		assert.Equal(t, "DDR5 ECC", result.Components.Memory[0].MemoryType)
		assert.Equal(t, uint32(8), result.Components.Memory[0].Count)
	})

	t.Run("high-performance compute with mixed memory types", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-hpc-01",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "AMD",
							Model:       "EPYC 9754",
							ThreadCount: 256,
							Count:       2,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 131072,
							MemoryType: "DDR5-4800",
							Count:      12,
						},
						{
							CapacityMb: 65536,
							MemoryType: "DDR5-5600",
							Count:      12,
						},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{
							Vendor:     "Micron",
							Model:      "9400 PRO",
							CapacityMb: 30720000,
							Count:      2,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "Lenovo",
						Model:  "ThinkSystem SR665 V3",
					},
					Tpm: &cwssaws.SkuComponentTpm{
						Vendor:  "Infineon",
						Version: "2.0",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)

		assert.NotNil(t, result)

		// Validate CPU
		assert.Len(t, result.Components.Cpus, 1)
		assert.Equal(t, "AMD", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "EPYC 9754", result.Components.Cpus[0].Model)
		assert.Equal(t, uint32(256), result.Components.Cpus[0].ThreadCount)

		// Validate mixed memory types
		assert.Len(t, result.Components.Memory, 2)
		assert.Equal(t, uint32(131072), result.Components.Memory[0].CapacityMb)
		assert.Equal(t, "DDR5-4800", result.Components.Memory[0].MemoryType)
		assert.Equal(t, uint32(65536), result.Components.Memory[1].CapacityMb)
		assert.Equal(t, "DDR5-5600", result.Components.Memory[1].MemoryType)

	})

	t.Run("edge computing configuration", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-edge-01",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "Intel",
							Model:       "Xeon D-2796NT",
							ThreadCount: 32,
							Count:       1,
						},
					},
					Gpus: []*cwssaws.SkuComponentGpu{
						{
							Vendor:      "NVIDIA",
							Model:       "T4",
							TotalMemory: "16GB GDDR6",
							Count:       2,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 32768,
							MemoryType: "DDR4-3200",
							Count:      4,
						},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{
							Vendor:     "Kingston",
							Model:      "DC1000B",
							CapacityMb: 960000,
							Count:      2,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "Cisco",
						Model:  "UCS C220 M6",
					},
					Tpm: &cwssaws.SkuComponentTpm{
						Vendor:  "Infineon",
						Version: "2.0",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)

		assert.NotNil(t, result)

		// Validate compact CPU
		assert.Len(t, result.Components.Cpus, 1)
		assert.Equal(t, "Intel", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "Xeon D-2796NT", result.Components.Cpus[0].Model)
		assert.Equal(t, uint32(1), result.Components.Cpus[0].Count)

		// Validate inference GPUs
		assert.Len(t, result.Components.Gpus, 1)
		assert.Equal(t, "T4", result.Components.Gpus[0].Model)
		assert.Equal(t, "16GB GDDR6", result.Components.Gpus[0].TotalMemory)
		assert.Equal(t, uint32(2), result.Components.Gpus[0].Count)

		// Validate compact storage
		assert.Len(t, result.Components.Storage, 1)
		assert.Equal(t, uint32(960000), result.Components.Storage[0].CapacityMb)
	})
}

func TestNewAPISkuSummary(t *testing.T) {
	type args struct {
		dbSku *cdbm.SKU
	}

	siteID := uuid.New()
	deviceType := "test-device-type"

	dbSku := &cdbm.SKU{
		ID:         "test-sku-id",
		SiteID:     siteID,
		DeviceType: &deviceType,
	}

	tests := []struct {
		name string
		args args
		want *APISkuSummary
	}{
		{
			name: "test new API SKU Summary",
			args: args{
				dbSku: dbSku,
			},
			want: &APISkuSummary{
				ID:         dbSku.ID,
				SiteID:     siteID.String(),
				DeviceType: &deviceType,
			},
		},
		{
			name: "test new API SKU Summary with nil input",
			args: args{
				dbSku: nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAPISkuSummary(tt.args.dbSku); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAPISkuSummary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAPISkuEdgeCases(t *testing.T) {
	siteID := uuid.New()
	createdTime := time.Now()
	updatedTime := time.Now()

	t.Run("SKU with nil DeviceType", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:                   "sku-no-device-type",
			SiteID:               siteID,
			DeviceType:           nil,
			AssociatedMachineIds: []string{"machine-1"},
			Created:              createdTime,
			Updated:              updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.Nil(t, result.DeviceType)
		assert.Equal(t, "sku-no-device-type", result.ID)
	})

	t.Run("SKU with empty AssociatedMachineIds", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:                   "sku-no-machines",
			SiteID:               siteID,
			AssociatedMachineIds: []string{},
			Created:              createdTime,
			Updated:              updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.Empty(t, result.AssociatedMachineIds)
	})

	t.Run("SKU with nil AssociatedMachineIds", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:                   "sku-nil-machines",
			SiteID:               siteID,
			AssociatedMachineIds: nil,
			Created:              createdTime,
			Updated:              updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.Nil(t, result.AssociatedMachineIds)
	})

	t.Run("SKU with many AssociatedMachineIds", func(t *testing.T) {
		machineIds := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			machineIds[i] = fmt.Sprintf("machine-%04d", i)
		}

		dbSku := &cdbm.SKU{
			ID:                   "sku-many-machines",
			SiteID:               siteID,
			AssociatedMachineIds: machineIds,
			Created:              createdTime,
			Updated:              updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.Len(t, result.AssociatedMachineIds, 1000)
		assert.Equal(t, "machine-0000", result.AssociatedMachineIds[0])
		assert.Equal(t, "machine-0999", result.AssociatedMachineIds[999])
	})

	t.Run("SKU with zero time values", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:      "sku-zero-time",
			SiteID:  siteID,
			Created: time.Time{},
			Updated: time.Time{},
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.True(t, result.Created.IsZero())
		assert.True(t, result.Updated.IsZero())
	})
}

func TestAPISkuComponentsWithSpecialValues(t *testing.T) {
	siteID := uuid.New()
	deviceType := "test-device"
	createdTime := time.Now()
	updatedTime := time.Now()

	t.Run("components with zero counts", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-zero-counts",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "Intel",
							Model:       "Test CPU",
							ThreadCount: 0,
							Count:       0,
						},
					},
					Gpus: []*cwssaws.SkuComponentGpu{
						{
							Vendor:      "NVIDIA",
							Model:       "Test GPU",
							TotalMemory: "0GB",
							Count:       0,
						},
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Components)
		assert.Len(t, result.Components.Cpus, 1)
		assert.Equal(t, uint32(0), result.Components.Cpus[0].Count)
		assert.Equal(t, uint32(0), result.Components.Cpus[0].ThreadCount)
		assert.Len(t, result.Components.Gpus, 1)
		assert.Equal(t, uint32(0), result.Components.Gpus[0].Count)
	})

	t.Run("components with very large counts", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-large-counts",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 4294967295, // max uint32
							MemoryType: "DDR5",
							Count:      4294967295,
						},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{
							Vendor:     "Test",
							Model:      "Large Storage",
							CapacityMb: 4294967295,
							Count:      4294967295,
						},
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Components)
		assert.Len(t, result.Components.Memory, 1)
		assert.Equal(t, uint32(4294967295), result.Components.Memory[0].CapacityMb)
		assert.Equal(t, uint32(4294967295), result.Components.Memory[0].Count)
	})

	t.Run("components with special characters in names", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-special-chars",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "Intel®",
							Model:       "Xeon® Platinum 8480+ (Sapphire Rapids)",
							ThreadCount: 112,
							Count:       2,
						},
					},
					Chassis: &cwssaws.SkuComponentChassis{
						Vendor: "HPE™",
						Model:  "ProLiant DL380 Gen11 (2U)",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Components)
		assert.Equal(t, "Intel®", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "Xeon® Platinum 8480+ (Sapphire Rapids)", result.Components.Cpus[0].Model)
		assert.Equal(t, "HPE™", result.Components.Chassis.Vendor)
	})

	t.Run("components with empty strings", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-empty-strings",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{
							Vendor:      "",
							Model:       "",
							ThreadCount: 64,
							Count:       1,
						},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{
							CapacityMb: 32768,
							MemoryType: "",
							Count:      4,
						},
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Components)
		assert.Equal(t, "", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "", result.Components.Cpus[0].Model)
		assert.Equal(t, "", result.Components.Memory[0].MemoryType)
	})

	t.Run("multiple components of each type", func(t *testing.T) {
		dbSku := &cdbm.SKU{
			ID:         "sku-multi-components",
			SiteID:     siteID,
			DeviceType: &deviceType,
			Components: &cdbm.SkuComponents{
				SkuComponents: &cwssaws.SkuComponents{
					Cpus: []*cwssaws.SkuComponentCpu{
						{Vendor: "Intel", Model: "CPU1", ThreadCount: 64, Count: 1},
						{Vendor: "Intel", Model: "CPU2", ThreadCount: 128, Count: 1},
						{Vendor: "AMD", Model: "CPU3", ThreadCount: 192, Count: 2},
					},
					Gpus: []*cwssaws.SkuComponentGpu{
						{Vendor: "NVIDIA", Model: "GPU1", TotalMemory: "40GB", Count: 2},
						{Vendor: "NVIDIA", Model: "GPU2", TotalMemory: "80GB", Count: 4},
						{Vendor: "AMD", Model: "GPU3", TotalMemory: "64GB", Count: 2},
					},
					Memory: []*cwssaws.SkuComponentMemory{
						{CapacityMb: 32768, MemoryType: "DDR4", Count: 8},
						{CapacityMb: 65536, MemoryType: "DDR5", Count: 8},
						{CapacityMb: 131072, MemoryType: "DDR5", Count: 4},
					},
					Storage: []*cwssaws.SkuComponentStorage{
						{Vendor: "Samsung", Model: "SSD1", CapacityMb: 960000, Count: 4},
						{Vendor: "Intel", Model: "SSD2", CapacityMb: 3840000, Count: 2},
						{Vendor: "Micron", Model: "SSD3", CapacityMb: 7680000, Count: 2},
					},
					Tpm: &cwssaws.SkuComponentTpm{
						Vendor:  "Infineon",
						Version: "2.0",
					},
				},
			},
			Created: createdTime,
			Updated: updatedTime,
		}

		result := NewAPISku(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Components)

		assert.Len(t, result.Components.Cpus, 3)
		assert.Equal(t, "Intel", result.Components.Cpus[0].Vendor)
		assert.Equal(t, "AMD", result.Components.Cpus[2].Vendor)

		assert.Len(t, result.Components.Gpus, 3)
		assert.Equal(t, "40GB", result.Components.Gpus[0].TotalMemory)
		assert.Equal(t, "80GB", result.Components.Gpus[1].TotalMemory)

		assert.Len(t, result.Components.Memory, 3)
		assert.Equal(t, uint32(32768), result.Components.Memory[0].CapacityMb)

		assert.Len(t, result.Components.Storage, 3)
		assert.Equal(t, "Samsung", result.Components.Storage[0].Vendor)

		assert.NotNil(t, result.Components.Tpm)
		assert.Equal(t, "Infineon", result.Components.Tpm.Vendor)
		assert.Equal(t, "2.0", result.Components.Tpm.Version)
	})
}

func TestAPISkuSummaryEdgeCases(t *testing.T) {
	t.Run("SKU Summary with nil DeviceType", func(t *testing.T) {
		siteID := uuid.New()
		dbSku := &cdbm.SKU{
			ID:         "sku-summary-no-type",
			SiteID:     siteID,
			DeviceType: nil,
		}

		result := NewAPISkuSummary(dbSku)
		assert.NotNil(t, result)
		assert.Nil(t, result.DeviceType)
		assert.Equal(t, "sku-summary-no-type", result.ID)
		assert.Equal(t, siteID.String(), result.SiteID)
	})

	t.Run("SKU Summary with empty DeviceType", func(t *testing.T) {
		siteID := uuid.New()
		emptyType := ""
		dbSku := &cdbm.SKU{
			ID:         "sku-summary-empty-type",
			SiteID:     siteID,
			DeviceType: &emptyType,
		}

		result := NewAPISkuSummary(dbSku)
		assert.NotNil(t, result)
		assert.NotNil(t, result.DeviceType)
		assert.Equal(t, "", *result.DeviceType)
	})

	t.Run("SKU Summary with special characters in DeviceType", func(t *testing.T) {
		siteID := uuid.New()
		specialType := "gpu-h100-80gb-sxm5_v2.1"
		dbSku := &cdbm.SKU{
			ID:         "sku-summary-special",
			SiteID:     siteID,
			DeviceType: &specialType,
		}

		result := NewAPISkuSummary(dbSku)
		assert.NotNil(t, result)
		assert.Equal(t, specialType, *result.DeviceType)
	})
}
