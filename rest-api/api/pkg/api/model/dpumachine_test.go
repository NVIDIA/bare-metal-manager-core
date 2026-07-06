// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestAPIDpuMachine_FromProto(t *testing.T) {
	site := &cdbm.Site{
		ID:                       uuid.New(),
		InfrastructureProviderID: uuid.New(),
		Name:                     "test-site",
		Status:                   "REGISTERED",
	}

	protoDpuMachine := &cwssaws.DpuMachine{
		Machine: &cwssaws.Machine{
			Id: &cwssaws.MachineId{
				Id: "test-machine-id",
			},
			DpuAgentVersion: cutil.GetPtr("1.0.0"),
			BmcInfo: &cwssaws.BmcInfo{
				Ip: cutil.GetPtr("10.0.0.1"),
			},
			DiscoveryInfo: &cwssaws.DiscoveryInfo{
				DmiData: &cwssaws.DmiData{
					BoardName:     "test-board-name",
					BoardSerial:   "test-board-serial",
					BoardVersion:  "test-board-version",
					BiosDate:      "test-bios-date",
					BiosVersion:   "test-bios-version",
					ProductSerial: "test-product-serial",
					ChassisSerial: "test-chassis-serial",
					ProductName:   "test-product-name",
					SysVendor:     "test-sys-vendor",
				},
			},
			Interfaces: []*cwssaws.MachineInterface{
				{
					Id: &cwssaws.MachineInterfaceId{
						Value: "test-interface-id",
					},
				},
			},
			Inventory: &cwssaws.MachineComponentInventory{
				Components: []*cwssaws.MachineInventorySoftwareComponent{
					{
						Name:    "test-software-component",
						Version: "test-software-component-version",
						Url:     "test-software-component-url",
					},
				},
			},
			Health: &cwssaws.HealthReport{
				Source:     "test-health-source",
				ObservedAt: timestamppb.New(time.Now()),
				Successes: []*cwssaws.HealthProbeSuccess{
					{
						Id:     "test-success-id",
						Target: cutil.GetPtr("test-success-target"),
					},
				},
				Alerts: []*cwssaws.HealthProbeAlert{
					{
						Id:           "test-alert-id",
						Target:       cutil.GetPtr("test-alert-target"),
						InAlertSince: nil,
						Classifications: []string{
							"test-alert-classification",
						},
						Message:       "test-alert-message",
						TenantMessage: nil,
					},
				},
			},
			Metadata: &cwssaws.Metadata{
				Labels: []*cwssaws.Label{
					{
						Key:   "env",
						Value: cutil.GetPtr("test"),
					},
				},
			},
		},
	}

	hostMachineID := "test-host-machine-id"
	dpuMachine := APIDpuMachine{}
	dpuMachine.FromProto(protoDpuMachine, APIDpuMachineProtoContext{
		HostMachineID:            hostMachineID,
		SiteID:                   site.ID,
		InfrastructureProviderID: site.InfrastructureProviderID,
	})

	assert.Equal(t, "test-machine-id", dpuMachine.ID)
	// HostMachineID must be the host Machine ID from the context, not the DPU's own ID.
	assert.Equal(t, hostMachineID, dpuMachine.HostMachineID)
	assert.NotEqual(t, dpuMachine.ID, dpuMachine.HostMachineID)
	assert.Equal(t, "1.0.0", dpuMachine.DpuAgentVersion)
	assert.Equal(t, "10.0.0.1", *dpuMachine.BMCInfo.IP)
	assert.Equal(t, "test-board-name", *dpuMachine.DMIData.BoardName)
	assert.Equal(t, "test-board-serial", *dpuMachine.DMIData.BoardSerial)
	assert.Equal(t, "test-board-version", *dpuMachine.DMIData.BoardVersion)
	assert.Equal(t, "test-product-name", *dpuMachine.DMIData.ProductName)
	assert.Equal(t, "test-sys-vendor", *dpuMachine.DMIData.SysVendor)
}

// TestAPIDpuMachine_FromProto_NilMachine guards against a panic when a
// DpuMachine proto carries no inner Machine (or interfaces with nil IDs):
// the Site worker / workflow could legitimately return such a shape, and the
// handler must surface a clean response rather than crash the process.
func TestAPIDpuMachine_FromProto_NilMachine(t *testing.T) {
	apdCtx := APIDpuMachineProtoContext{
		SiteID:                   uuid.New(),
		InfrastructureProviderID: uuid.New(),
	}

	assert.NotPanics(t, func() {
		apd := APIDpuMachine{}
		apd.FromProto(&cwssaws.DpuMachine{Machine: nil}, apdCtx)
	})

	assert.NotPanics(t, func() {
		apdi := APIDpuMachineInterface{}
		apdi.FromProto(&cwssaws.MachineInterface{})
	})
}

func TestNewAPIDpuMachines(t *testing.T) {
	ctx := APIDpuMachineProtoContext{
		HostMachineID:            "test-host-machine-id",
		SiteID:                   uuid.New(),
		InfrastructureProviderID: uuid.New(),
	}
	protoDpuMachines := []*cwssaws.DpuMachine{
		nil,
		{
			Machine: &cwssaws.Machine{
				Id:    &cwssaws.MachineId{Id: "test-dpu-machine-id-1"},
				State: "READY",
			},
		},
		{
			Machine: &cwssaws.Machine{
				Id:    &cwssaws.MachineId{Id: "test-dpu-machine-id-2"},
				State: "READY",
			},
		},
	}

	apiDpuMachines := NewAPIDpuMachines(protoDpuMachines, ctx)

	assert.Len(t, apiDpuMachines, 2)
	assert.Equal(t, "test-dpu-machine-id-1", apiDpuMachines[0].ID)
	assert.Equal(t, "test-dpu-machine-id-2", apiDpuMachines[1].ID)
	assert.Equal(t, ctx.HostMachineID, apiDpuMachines[0].HostMachineID)
	assert.Equal(t, ctx.SiteID.String(), apiDpuMachines[0].SiteID)
	assert.Equal(t, ctx.InfrastructureProviderID.String(), apiDpuMachines[0].InfrastructureProviderID)
}
