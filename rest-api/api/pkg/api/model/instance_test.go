// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAPIInstance(t *testing.T) {
	dbs := &cdbm.Site{
		ID:                       uuid.New(),
		Name:                     "test-name",
		Description:              cdb.GetStrPtr("Test Description"),
		InfrastructureProviderID: uuid.New(),
		SerialConsoleHostname:    cdb.GetStrPtr("test-hostname"),
	}

	instanceTypeID := uuid.New()
	dbi1 := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "test-name",
		TenantID:                 uuid.New(),
		InfrastructureProviderID: dbs.InfrastructureProviderID,
		SiteID:                   dbs.ID,
		InstanceTypeID:           &instanceTypeID,
		VpcID:                    uuid.New(),
		MachineID:                cdb.GetStrPtr(uuid.NewString()),
		ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
		OperatingSystemID:        nil,
		IpxeScript:               cdb.GetStrPtr("test"),
		AlwaysBootWithCustomIpxe: true,
		UserData:                 cdb.GetStrPtr("test"),
		Labels: map[string]string{
			"test": "test",
		},
		TpmEkCertificate: cdb.GetStrPtr("test"),
		Status:           cdbm.InstanceStatusPending,
		Created:          time.Now(),
		Updated:          time.Now(),
	}

	dbsd1 := cdbm.StatusDetail{
		ID:       uuid.New(),
		EntityID: dbi1.ID.String(),
		Status:   cdbm.InstanceStatusPending,
		Message:  cdb.GetStrPtr("test-message"),
		Created:  time.Now(),
		Updated:  time.Now(),
	}

	dbis1 := cdbm.Interface{
		ID:          uuid.New(),
		InstanceID:  dbi1.ID,
		SubnetID:    cdb.GetUUIDPtr(uuid.New()),
		IsPhysical:  true,
		MacAddress:  cdb.GetStrPtr("test-mac-address"),
		IPAddresses: []string{"12.70.0.1"},
		Status:      cdbm.InterfaceStatusPending,
		Created:     time.Now(),
		Updated:     time.Now(),
	}

	secondaryVpcID1 := uuid.New()
	secondaryVpcID2 := uuid.New()

	dbis1Secondary1 := cdbm.Interface{
		ID:          uuid.New(),
		InstanceID:  dbi1.ID,
		VpcPrefixID: cdb.GetUUIDPtr(uuid.New()),
		VpcPrefix: &cdbm.VpcPrefix{
			ID:    uuid.New(),
			VpcID: secondaryVpcID1,
		},
		IsPhysical: false,
		Status:     cdbm.InterfaceStatusPending,
		Created:    time.Now(),
		Updated:    time.Now(),
	}

	dbis1Secondary2 := cdbm.Interface{
		ID:          uuid.New(),
		InstanceID:  dbi1.ID,
		VpcPrefixID: cdb.GetUUIDPtr(uuid.New()),
		VpcPrefix: &cdbm.VpcPrefix{
			ID:    uuid.New(),
			VpcID: secondaryVpcID2,
		},
		IsPhysical: false,
		Status:     cdbm.InterfaceStatusPending,
		Created:    time.Now(),
		Updated:    time.Now(),
	}

	dbibi1 := cdbm.InfiniBandInterface{
		ID:                    uuid.New(),
		InstanceID:            dbi1.ID,
		SiteID:                dbi1.SiteID,
		InfiniBandPartitionID: uuid.New(),
		DeviceInstance:        2,
		IsPhysical:            false,
		VirtualFunctionID:     cdb.GetIntPtr(2),
		Status:                cdbm.InfiniBandInterfaceStatusPending,
		Created:               time.Now(),
		Updated:               time.Now(),
	}

	dbnvl1 := cdbm.NVLinkInterface{
		ID:                       uuid.New(),
		InstanceID:               dbi1.ID,
		SiteID:                   dbi1.SiteID,
		NVLinkLogicalPartitionID: uuid.New(),
		Device:                   cdb.GetStrPtr("NVIDIA GB200"),
		DeviceInstance:           0,
		Status:                   cdbm.NVLinkInterfaceStatusPending,
		Created:                  time.Now(),
		Updated:                  time.Now(),
	}

	instanceTypeID = uuid.New()
	dbi2 := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "test-name",
		TenantID:                 uuid.New(),
		InfrastructureProviderID: uuid.New(),
		SiteID:                   uuid.New(),
		InstanceTypeID:           &instanceTypeID,
		VpcID:                    uuid.New(),
		MachineID:                cdb.GetStrPtr(uuid.NewString()),
		ControllerInstanceID:     cdb.GetUUIDPtr(uuid.New()),
		OperatingSystemID:        cdb.GetUUIDPtr(uuid.New()),
		IpxeScript:               cdb.GetStrPtr("test"),
		AlwaysBootWithCustomIpxe: true,
		UserData:                 cdb.GetStrPtr("test"),
		Status:                   cdbm.InstanceStatusReady,
		TpmEkCertificate:         cdb.GetStrPtr("test"),
		PowerStatus:              cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
		Created:                  time.Now(),
		Updated:                  time.Now(),
	}

	dbsd2 := cdbm.StatusDetail{
		ID:       uuid.New(),
		EntityID: dbi1.ID.String(),
		Status:   cdbm.InstanceStatusReady,
		Message:  cdb.GetStrPtr("test-message"),
		Created:  time.Now(),
		Updated:  time.Now(),
	}

	dbis2 := cdbm.Interface{
		ID:                 uuid.New(),
		InstanceID:         dbi1.ID,
		SubnetID:           cdb.GetUUIDPtr(uuid.New()),
		MachineInterfaceID: cdb.GetUUIDPtr(uuid.New()),
		Status:             cdbm.InterfaceStatusPending,
		Created:            time.Now(),
		Updated:            time.Now(),
	}

	dbdes := cdbm.DpuExtensionService{
		ID:          uuid.New(),
		Name:        "test-service",
		ServiceType: "test-type",
		Version:     cdb.GetStrPtr("v1"),
		VersionInfo: &cdbm.DpuExtensionServiceVersionInfo{
			Version:        "v1",
			Data:           "apiVersion: v1\nkind: Pod",
			HasCredentials: true,
			Created:        time.Now(),
		},
		Status:  cdbm.DpuExtensionServiceStatusReady,
		Created: time.Now(),
		Updated: time.Now(),
	}

	dbdesd2 := cdbm.DpuExtensionServiceDeployment{
		ID:                    uuid.New(),
		InstanceID:            dbi2.ID,
		DpuExtensionServiceID: dbdes.ID,
		DpuExtensionService:   &dbdes,
		SiteID:                dbdes.SiteID,
		TenantID:              dbdes.TenantID,
		Version:               *dbdes.Version,
		Status:                cdbm.DpuExtensionServiceDeploymentStatusRunning,
		Created:               time.Now(),
		Updated:               time.Now(),
	}

	dbskg := cdbm.SSHKeyGroup{
		ID:      uuid.New(),
		Name:    "test-group",
		Version: cdb.GetStrPtr("1213123"),
		Status:  cdbm.SSHKeyGroupStatusSynced,
		Created: time.Now(),
		Updated: time.Now(),
	}

	dbskg2 := cdbm.SSHKeyGroup{
		ID:      uuid.New(),
		Name:    "test-group-2",
		Version: cdb.GetStrPtr("1213123"),
		Status:  cdbm.SSHKeyGroupStatusSynced,
		Created: time.Now(),
		Updated: time.Now(),
	}

	type args struct {
		dbic                    *cdbm.Instance
		dbs                     *cdbm.Site
		dbsds                   []cdbm.StatusDetail
		dbis                    []cdbm.Interface
		dbibi                   []cdbm.InfiniBandInterface
		dbdesd                  []cdbm.DpuExtensionServiceDeployment
		dbnvl                   []cdbm.NVLinkInterface
		dbskg                   []cdbm.SSHKeyGroup
		expectedSecondaryVpcIDs []string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test new API Instance initializer",
			args: args{
				dbic:                    dbi1,
				dbs:                     dbs,
				dbsds:                   []cdbm.StatusDetail{dbsd1},
				dbis:                    []cdbm.Interface{dbis1, dbis1Secondary2, dbis1Secondary1},
				dbibi:                   []cdbm.InfiniBandInterface{dbibi1},
				dbnvl:                   []cdbm.NVLinkInterface{dbnvl1},
				dbskg:                   []cdbm.SSHKeyGroup{dbskg, dbskg2},
				expectedSecondaryVpcIDs: []string{secondaryVpcID1.String(), secondaryVpcID2.String()},
			},
		},
		{
			name: "test new API Instance initializer with power status change",
			args: args{
				dbic:   dbi2,
				dbs:    dbs,
				dbsds:  []cdbm.StatusDetail{dbsd2},
				dbis:   []cdbm.Interface{dbis2},
				dbdesd: []cdbm.DpuExtensionServiceDeployment{dbdesd2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAPIInstance(tt.args.dbic, tt.args.dbs, tt.args.dbis, tt.args.dbibi, tt.args.dbdesd, tt.args.dbnvl, tt.args.dbskg, tt.args.dbsds)
			marshalled, err := json.Marshal(got)
			assert.NoError(t, err)
			var roundTripped APIInstance
			err = json.Unmarshal(marshalled, &roundTripped)
			assert.NoError(t, err)

			assert.Equal(t, tt.args.dbic.ID.String(), got.ID)
			assert.Equal(t, tt.args.dbic.Name, got.Name)
			assert.Equal(t, tt.args.dbic.TenantID.String(), got.TenantID)
			assert.Equal(t, tt.args.dbic.InfrastructureProviderID.String(), got.InfrastructureProviderID)
			assert.Equal(t, tt.args.dbic.SiteID.String(), got.SiteID)
			assert.Equal(t, tt.args.dbic.InstanceTypeID.String(), *got.InstanceTypeID)
			assert.Equal(t, tt.args.dbic.VpcID.String(), got.VpcID)
			if got.MachineID != nil {
				assert.Equal(t, *tt.args.dbic.MachineID, *got.MachineID)
			}
			if got.OperatingSystemID != nil {
				assert.Equal(t, tt.args.dbic.OperatingSystemID.String(), *got.OperatingSystemID)
			}
			if got.IpxeScript != nil {
				assert.Equal(t, *tt.args.dbic.IpxeScript, *got.IpxeScript)
			}
			assert.Equal(t, got.AlwaysBootWithCustomIpxe, true)
			if got.UserData != nil {
				assert.Equal(t, *tt.args.dbic.UserData, *got.UserData)
			}

			if got.Labels != nil {
				assert.Equal(t, tt.args.dbic.Labels, got.Labels)
			}

			if tt.args.expectedSecondaryVpcIDs != nil {
				expectedSecondaryVpcIDs := slices.Clone(tt.args.expectedSecondaryVpcIDs)
				slices.Sort(expectedSecondaryVpcIDs)
				assert.Equal(t, expectedSecondaryVpcIDs, roundTripped.SecondaryVpcIDs)
			}

			if tt.args.dbic.PowerStatus != nil && *tt.args.dbic.PowerStatus != cdbm.InstancePowerStatusBootCompleted {
				assert.Equal(t, *tt.args.dbic.PowerStatus, got.Status)
			} else {
				assert.Equal(t, tt.args.dbic.Status, got.Status)
			}

			assert.Equal(t, tt.args.dbic.ControllerInstanceID.String(), got.ControllerInstanceID)
			assert.Equal(t, tt.args.dbic.Created, got.Created)
			assert.Equal(t, tt.args.dbic.Updated, got.Updated)

			serialConsoleURL := fmt.Sprintf("ssh://%s@%s", tt.args.dbic.ControllerInstanceID.String(), *dbs.SerialConsoleHostname)

			assert.Equal(t, serialConsoleURL, *got.SerialConsoleURL)

			assert.Equal(t, serialConsoleURL, *got.SerialConsoleURL)
			assert.Equal(t, len(tt.args.dbsds), len(got.StatusHistory))

			assert.Equal(t, len(tt.args.dbis), len(got.Interfaces))
			assert.Equal(t, tt.args.dbis[0].ID.String(), got.Interfaces[0].ID)
			assert.Equal(t, tt.args.dbis[0].InstanceID.String(), got.Interfaces[0].InstanceID)
			assert.Equal(t, tt.args.dbis[0].SubnetID.String(), *got.Interfaces[0].SubnetID)
			assert.Equal(t, tt.args.dbis[0].IsPhysical, got.Interfaces[0].IsPhysical)
			if got.Interfaces[0].MacAddress != nil {
				assert.Equal(t, *tt.args.dbis[0].MacAddress, *got.Interfaces[0].MacAddress)
			}
			assert.Equal(t, tt.args.dbis[0].IPAddresses, got.Interfaces[0].IPAddresses)
			assert.Equal(t, tt.args.dbis[0].Status, got.Interfaces[0].Status)
			assert.Equal(t, tt.args.dbis[0].Created, got.Interfaces[0].Created)
			assert.Equal(t, tt.args.dbis[0].Updated, got.Interfaces[0].Updated)

			assert.Equal(t, len(tt.args.dbibi), len(got.InfiniBandInterfaces))
			if len(tt.args.dbibi) > 0 {
				assert.Equal(t, tt.args.dbibi[0].ID.String(), got.InfiniBandInterfaces[0].ID)
				assert.Equal(t, tt.args.dbibi[0].InfiniBandPartitionID.String(), got.InfiniBandInterfaces[0].InfiniBandPartitonID)
				assert.Equal(t, tt.args.dbibi[0].DeviceInstance, got.InfiniBandInterfaces[0].DeviceInstance)
				assert.Equal(t, tt.args.dbibi[0].IsPhysical, got.InfiniBandInterfaces[0].IsPhysical)
				assert.Equal(t, tt.args.dbibi[0].VirtualFunctionID, got.InfiniBandInterfaces[0].VirtualFunctionID)
			}

			assert.Equal(t, len(tt.args.dbdesd), len(got.DpuExtensionServiceDeployments))
			if len(tt.args.dbdesd) > 0 {
				assert.Equal(t, tt.args.dbdesd[0].ID.String(), got.DpuExtensionServiceDeployments[0].ID)
				assert.Equal(t, tt.args.dbdesd[0].DpuExtensionServiceID.String(), got.DpuExtensionServiceDeployments[0].DpuExtensionService.ID)
				assert.Equal(t, tt.args.dbdesd[0].Version, got.DpuExtensionServiceDeployments[0].Version)
			}

			assert.Equal(t, len(tt.args.dbnvl), len(got.NVLinkInterfaces))
			if len(tt.args.dbnvl) > 0 {
				assert.Equal(t, tt.args.dbnvl[0].ID.String(), got.NVLinkInterfaces[0].ID)
				assert.Equal(t, tt.args.dbnvl[0].NVLinkLogicalPartitionID.String(), got.NVLinkInterfaces[0].NVLinkLogicalPartitionID)
				assert.Equal(t, tt.args.dbnvl[0].DeviceInstance, got.NVLinkInterfaces[0].DeviceInstance)
			}

			assert.Equal(t, len(tt.args.dbskg), len(got.SSHKeyGroupIDs))
			assert.Equal(t, len(tt.args.dbskg), len(got.SSHKeyGroups))

			assert.Equal(t, *tt.args.dbic.TpmEkCertificate, *got.TpmEkCertificate)

			jsonResp, err := json.Marshal(got)
			assert.NoError(t, err)
			var attrMap map[string]interface{}
			err = json.Unmarshal(jsonResp, &attrMap)
			assert.NoError(t, err)
		})
	}
}

func TestAPIInstanceCreateRequest_Validate(t *testing.T) {
	type fields struct {
		Name                           string
		Description                    *string
		TenantID                       string
		InstanceTypeID                 string
		VpcID                          string
		SecondaryVpcIDs                []string
		OperatingSystemID              *string
		IpxeScript                     *string
		UserData                       *string
		Interfaces                     []APIInterfaceCreateOrUpdateRequest
		InfiniBandInterfaces           []APIInfiniBandInterfaceCreateOrUpdateRequest
		DpuExtensionServiceDeployments []APIDpuExtensionServiceDeploymentRequest
		NVLinkInterfaces               []APINVLinkInterfaceCreateOrUpdateRequest
		Labels                         map[string]string
	}
	tests := []struct {
		name                 string
		fields               fields
		checkDefaultPhysical bool
		wantErr              bool
		wantErrorMessage     string
	}{
		{
			name: "test valid Instance with subnet create request",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			checkDefaultPhysical: true,
			wantErr:              false,
		},
		{
			name: "test valid Instance with InfiniBand interface create request",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				InfiniBandInterfaces: []APIInfiniBandInterfaceCreateOrUpdateRequest{
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        0,
						IsPhysical:            true,
					},
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        1,
						IsPhysical:            true,
					},
				},
			},
			checkDefaultPhysical: true,
			wantErr:              false,
		},
		{
			name: "test valid Instance create request - DpuExtensionServiceDeployment create request",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				DpuExtensionServiceDeployments: []APIDpuExtensionServiceDeploymentRequest{
					{
						DpuExtensionServiceID: uuid.NewString(),
						Version:               "v1",
					},
					{
						DpuExtensionServiceID: uuid.NewString(),
						Version:               "v2",
					},
				},
			},
		},
		{
			name: "test valid Instance create request - physical interface specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: true,
					},
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: false,
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test valid Instance create request - invalid names are specified names exceeded 256 char",
			fields: fields{
				Name:              "apvhhigcgctlgiwtbrgldkegmnwuqcibutndlholygxvhzrpinziepszvpmopvzkybykrwgvzojtssorabkrnawgjzeuuerphsnecipubeuzrpewkfuvwoeybagaxpvjvzvbzqznyfmcpbxrhbdkhewiepykfjeejeqatswgrlhqkgnvwqmatejufnsjgelcugcoccybywdrnlyvsegsegorygwdvurgktpuzyrsoutspsnyzynliaxwseazqmimp",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request - invalid description are specified description exceeded 1024 char",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("rkbfdrkybjqtrvgeqjubtkeoolyhxicmnisgpaffhdldzgciilwbwqglwglqiibcntguwihfxttrwqvyneomiqaseaxfaeblkavuskxhpbxjbzvbtdbxmrqmgekhqtbsqhgiuirtppkurmwtzemljjzajnwqaqijefyvoqufjopbkepizjurtgezlivtwkmemfdjtkdskbtqkrkcpozdwjplhszfabwhfygxonkgjgctlulkvkqzxrngzuqgrkunwcafpamvynsjtvayqdlrbafirygnlrngxhkxccowqygidzocwbnyhebvtisdimfjqnceznffsiscdshbsrdhnggyskqawlltbmidtisehwryfwmfpvisjyqgcoekxemhixvsxgrwkhlqmkhbtrcnhrdfsakumvqtggmymnomwxvxnqdlcqzlerjrvzuxhunmdilxawtuxgmsnljhdromaoelxgzfsgnhttulfqwzxvufqpoxadlbnmbtlckxgrzfirvscbpzanhrhgvrsdmkqfahfridkdlhgbjvdenhibsfjdgbaiszwyqilhslwvxtstrtmdvumdtpruduviujwytepzxzexbjnuizhpvufzcjicrlaqsvufrivvsgbcrqaztasucyjtfefbxoolzmgshhjeegmwcziqgjhninqphkvgpguquikakbljemkvbpfajumhlaiahaijvdsodklqsxorsdtiksqfhmnrutafnyqqswfmfzahwmucyhwzgxthnedcfuaptaqzylwuljaxybgyenybekgkfgmpxmkcvcmyxyazykchibcugfcwxezqcwmghjweppuisyttkaodulvgzpwfzdtstvvotulpookzpwxoyqhdzcljsguieoijbsoprtfbgzuoiiogudmjpabkfiydqyatymujnfpdhugbijaawzbohqfkvlbaojsasbyrxrapdphqmnqabpbrcowvxfwlfabbmijdabqacvpokeogjhhmoswfqulgzly"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request - accept description as empty string",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr(""),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: true,
					},
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: false,
					},
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test invalid Instance create request - invalid VPC ID",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             "invalid-uuid",
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance Type create request - invalid Subnet ID",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr("invalid-uuid"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance Type create request, no Subnet specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces:        []APIInterfaceCreateOrUpdateRequest{},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance create request, Invalid Subnet, multiple physical interface has been set",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: true,
					},
					{
						SubnetID:   cdb.GetStrPtr(uuid.NewString()),
						IsPhysical: true,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance create request, DpuExtensionServiceDeployment create request with invalid DpuExtensionServiceID",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				DpuExtensionServiceDeployments: []APIDpuExtensionServiceDeploymentRequest{
					{
						DpuExtensionServiceID: "invalid-uuid",
						Version:               "v1",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance create request, DpuExtensionServiceDeployment create request with duplicate service and version",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				DpuExtensionServiceDeployments: []APIDpuExtensionServiceDeploymentRequest{
					{
						DpuExtensionServiceID: "c35af8c2-6073-4752-b3cb-eff40de45a20",
						Version:               "v1",
					},
					{
						DpuExtensionServiceID: "c35af8c2-6073-4752-b3cb-eff40de45a20",
						Version:               "v1",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance create request, no Interfaces specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request, subnet Interfaces specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test valid Instance create request, Vpcprefix Interfaces specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
						IsPhysical:  true,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test invalid Instance create request, both subnet and vpcprefix specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
					{
						VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request, no Operating System specified",
			fields: fields{
				Name:           "test-name",
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr("test-ipxe-script"),
				UserData:       cdb.GetStrPtr("test-user-data"),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test invalid Instance create request, no Operating System and empty ipxeScript specified",
			fields: fields{
				Name:           "test-name",
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr(""),
				UserData:       cdb.GetStrPtr("test-user-data"),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request - valid labels are specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				Labels: map[string]string{
					"name":        "a-nv100-instance",
					"description": "",
				},
			},
			wantErr: false,
		},
		{
			name: "test valid Instance create request - invalid labels are specified key is empty",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				Labels: map[string]string{
					"name": "a-nv200=instance",
					"":     "test",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request - invalid labels are specified both key and value are empty",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				Labels: map[string]string{
					"name": "a-nv300=instance",
					"":     "",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid Instance create request - invalid labels are specified key has char more than 255",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
				Labels: map[string]string{
					"ynGJz5YL06ZA9OZfNTUTId77jNrYPilVe9MLea1MGXHwueojLYbhvheA7obW06etCPpAis8199Giktlpn1cxDDIsHiFcGr5JR25XXhB16F3DNnTUwdoFgsB1wH1uXioISTohUo2CjXKIbrGaXQoMM6oBPTJFyIMwph3fJx4lNa8cPPP5Vdfq2WKjuVeS5t2Dv8rlNjguc3J3siYlkuL7KxEmkModeq9W0j1plWv1yVKjBxVeu013XzCCicVSPtj2HQFO2O6rtg": "a-nv300=instance",
				},
			},
			wantErr:          true,
			wantErrorMessage: "label key must contain at least 1 character and a maximum of 255 characters.",
		},
		{
			name: "test invalid Instance create request, secondary VPCs require vpcPrefix interfaces",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				SecondaryVpcIDs:   []string{uuid.NewString()},
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr:          true,
			wantErrorMessage: "`secondaryVpcIds` can only be specified when `vpcPrefixId` is specified within `interfaces`",
		},
		{
			name: "test valid Instance create request, NVLink Interfaces specified",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				NVLinkInterfaces: []APINVLinkInterfaceCreateOrUpdateRequest{
					{
						NVLinkLogicalPartitionID: uuid.NewString(),
						DeviceInstance:           0,
					},
				},
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "test invalid Instance create request, NVLink Interfaces specified with device instance out of range",
			fields: fields{
				Name:              "test-name",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				NVLinkInterfaces: []APINVLinkInterfaceCreateOrUpdateRequest{
					{
						NVLinkLogicalPartitionID: uuid.NewString(),
						DeviceInstance:           4,
					},
				},
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr:          true,
			wantErrorMessage: "deviceInstance: deviceInstance must be between 0 and 3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icr := APIInstanceCreateRequest{
				Name:                           tt.fields.Name,
				Description:                    tt.fields.Description,
				TenantID:                       tt.fields.TenantID,
				InstanceTypeID:                 &tt.fields.InstanceTypeID,
				VpcID:                          tt.fields.VpcID,
				SecondaryVpcIDs:                tt.fields.SecondaryVpcIDs,
				OperatingSystemID:              tt.fields.OperatingSystemID,
				IpxeScript:                     tt.fields.IpxeScript,
				UserData:                       tt.fields.UserData,
				Interfaces:                     tt.fields.Interfaces,
				InfiniBandInterfaces:           tt.fields.InfiniBandInterfaces,
				DpuExtensionServiceDeployments: tt.fields.DpuExtensionServiceDeployments,
				NVLinkInterfaces:               tt.fields.NVLinkInterfaces,
				Labels:                         tt.fields.Labels,
			}

			err := icr.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIInstanceCreateRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}

			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}

			if tt.checkDefaultPhysical {
				if tt.fields.Interfaces != nil {
					assert.True(t, tt.fields.Interfaces[0].IsPhysical)
				}
			}
		})
	}
}

func TestAPIBatchInstanceCreateRequest_Validate(t *testing.T) {
	tests := []struct {
		name             string
		req              APIBatchInstanceCreateRequest
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name: "succeeds without requested interface ip",
			req: APIBatchInstanceCreateRequest{
				NamePrefix:     "test-batch",
				Count:          2,
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr("test ipxe"),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{SubnetID: cdb.GetStrPtr(uuid.NewString())},
				},
			},
			wantErr: false,
		},
		{
			name: "fails when any interface uses requested ip",
			req: APIBatchInstanceCreateRequest{
				NamePrefix:     "test-batch",
				Count:          2,
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr("test ipxe"),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
						IPAddress:   cdb.GetStrPtr("10.0.0.11"),
					},
				},
			},
			wantErr:          true,
			wantErrorMessage: "batch instance create does not support `ipAddress` on interfaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIBatchInstanceCreateRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}

			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}
		})
	}
}

func TestAPIInstanceCreateRequest_ValidateAndSetOperatingSystemData(t *testing.T) {

	cfg1 := config.NewConfig()

	cfg1.SetSitePhoneHomeUrl("http://localhost/local")

	type fields struct {
		Name                     string
		Description              *string
		TenantID                 string
		InstanceTypeID           string
		VpcID                    string
		OperatingSystemID        *string
		IpxeScript               *string
		UserData                 *string
		PhoneHomeEnabled         *bool
		AlwaysBootWithCustomIpxe *bool
	}

	os := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(util.TestCommonCloudInit),
		PhoneHomeEnabled: true,
		IsActive:         true,
		Status:           cdbm.OperatingSystemStatusReady,
		AllowOverride:    true,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	osNoOverride := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(util.TestCommonCloudInit),
		PhoneHomeEnabled: true,
		IsActive:         true,
		Status:           cdbm.OperatingSystemStatusReady,
		AllowOverride:    false,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	imageOs := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "image_os",
		IpxeScript:       nil,
		UserData:         nil,
		PhoneHomeEnabled: false,
		IsActive:         true,
		Status:           cdbm.OperatingSystemStatusReady,
		AllowOverride:    false,
		Type:             cdbm.OperatingSystemTypeImage,
		CreatedBy:        uuid.New(),
	}

	imageOSDeactivated := new(cdbm.OperatingSystem)
	*imageOSDeactivated = *imageOs
	imageOSDeactivated.IsActive = false
	imageOSDeactivated.ID = uuid.New()

	tests := []struct {
		name         string
		fields       fields
		cfg          *config.Config
		os           *cdbm.OperatingSystem
		wantUserData *string
		wantErr      bool
	}{
		{
			name: "ipxe os selected, os has user-data, no override allowed, user-data specified, should fail",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("some user data"),
			},
			os:      osNoOverride,
			cfg:     cfg1,
			wantErr: true,
		},
		{
			name: "ipxe os selected, os has user-data, no override allowed, user-data not specified, should succeed",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
			},
			os:      osNoOverride,
			cfg:     cfg1,
			wantErr: false,
		},
		{
			name: "image os selected, iPXE specified, should fail",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          nil,
			},
			os:      imageOs,
			cfg:     cfg1,
			wantErr: true,
		},
		{
			name: "image os selected, phone-enabled, should succeed",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        nil,
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			os:      imageOs,
			cfg:     cfg1,
			wantErr: false,
		},
		{
			name: "deactivated image os selected, should fail",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          nil,
			},
			os:      imageOSDeactivated,
			cfg:     cfg1,
			wantErr: true,
		},
		{
			name: "image os selected, AlwaysBootWithCustomIpxe selected, should fail",
			fields: fields{
				Name:                     "test-name",
				Description:              cdb.GetStrPtr("Test description"),
				TenantID:                 uuid.NewString(),
				InstanceTypeID:           uuid.NewString(),
				VpcID:                    uuid.NewString(),
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				UserData:                 nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: cdb.GetBoolPtr(true),
			},
			os:      imageOs,
			cfg:     cfg1,
			wantErr: true,
		},
		{
			name: "os is nil, no iPXE specified, should fail",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        nil,
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr: true,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is nil when OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr: false,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is invalid when OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("test"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr: true,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance create request when phone home flag is disabled, userData is non YAML and OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("test-user-data"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr: false,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance create request when phone home flag is not specified, userData is non YAML and OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("test-user-data"),
			},
			wantErr: false,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance create request when phone home flag is specified but disabled, userData is non YAML, and OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("test-user-data:\ninvalid\n"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantUserData: cdb.GetStrPtr("test-user-data:\ninvalid\n"),
			wantErr:      false,
			cfg:          cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is valid when OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr(util.TestCommonCloudInit),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr: false,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is technically valid but functionally empty when OS in nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("#cloud-config"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr: true,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is technically valid but functionally empty when OS in nil, but phonehome disabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				UserData:          cdb.GetStrPtr("#cloud-config"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr: false,
			cfg:     cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when OS in present with phonehome",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(os.ID.String()),
				UserData:          nil,
				PhoneHomeEnabled:  nil,
			},
			wantErr: false,
			cfg:     cfg1,
			os:      os,
		},
		{
			name: "test valid Instance PhoneHome enabled create request when OS in present with phonehome, userData does't contain phone home url",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          uuid.NewString(),
				InstanceTypeID:    uuid.NewString(),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(os.ID.String()),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr: false,
			cfg:     cfg1,
			os:      os,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icr := APIInstanceCreateRequest{
				Name:                     tt.fields.Name,
				Description:              tt.fields.Description,
				TenantID:                 tt.fields.TenantID,
				InstanceTypeID:           &tt.fields.InstanceTypeID,
				VpcID:                    tt.fields.VpcID,
				OperatingSystemID:        tt.fields.OperatingSystemID,
				IpxeScript:               tt.fields.IpxeScript,
				UserData:                 tt.fields.UserData,
				PhoneHomeEnabled:         tt.fields.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: tt.fields.AlwaysBootWithCustomIpxe,
			}

			err := icr.ValidateAndSetOperatingSystemData(cfg1, tt.os)
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIInstanceCreateRequest.ValidateAndSetOperatingSystemData() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}

			if err != nil {
				return
			}

			if tt.wantUserData != nil {
				assert.NotNil(t, icr.UserData)
				assert.Contains(t, *icr.UserData, *tt.wantUserData)
			}

			if (icr.PhoneHomeEnabled != nil && *icr.PhoneHomeEnabled) || (icr.PhoneHomeEnabled == nil && tt.os != nil && tt.os.PhoneHomeEnabled) {
				assert.NotNil(t, icr.UserData)
				assert.Contains(t, *icr.UserData, tt.cfg.GetSitePhoneHomeUrl())
			}

			if icr.PhoneHomeEnabled != nil && !*icr.PhoneHomeEnabled {
				assert.NotContains(t, *icr.UserData, tt.cfg.GetSitePhoneHomeUrl())
			}
		})
	}
}

func TestAPIInstanceUpdateRequest_Validate(t *testing.T) {
	type fields struct {
		Name                     *string
		Description              *string
		Labels                   map[string]string
		TriggerReboot            *bool
		RebootWithCustomIpxe     *bool
		ApplyUpdatesOnReboot     *bool
		OperatingSystemID        *string
		IpxeScript               *string
		UserData                 *string
		PhoneHomeEnabled         *bool
		AlwaysBootWithCustomIpxe *bool
		SecondaryVpcIDs          []string
		Interfaces               []APIInterfaceCreateOrUpdateRequest
		InfiniBandInterfaces     []APIInfiniBandInterfaceCreateOrUpdateRequest
		NVLinkInterfaces         []APINVLinkInterfaceCreateOrUpdateRequest
		SSHKeyGroupIDs           []string
		NetworkSecurityGroupID   *string
	}
	tests := []struct {
		name              string
		fields            fields
		wantErr           bool
		wantUpdateRequest *bool
	}{
		{
			name: "test valid Instance config update request",
			fields: fields{
				Name:              cdb.GetStrPtr("test-name"),
				Description:       cdb.GetStrPtr("Test description"),
				Labels:            map[string]string{"name": "test-name", "description": "Test description"},
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
				SecondaryVpcIDs:   []string{uuid.NewString()},
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
						IsPhysical:  false,
					},
				},
				InfiniBandInterfaces: []APIInfiniBandInterfaceCreateOrUpdateRequest{
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        0,
						IsPhysical:            true,
					},
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        1,
						IsPhysical:            true,
					},
				},
				SSHKeyGroupIDs:         []string{uuid.NewString()},
				NetworkSecurityGroupID: cdb.GetStrPtr(uuid.NewString()),
			},
			wantErr:           false,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test valid Instance reboot request",
			fields: fields{
				TriggerReboot:        cdb.GetBoolPtr(true),
				RebootWithCustomIpxe: cdb.GetBoolPtr(true),
				ApplyUpdatesOnReboot: cdb.GetBoolPtr(true),
			},
			wantErr:           false,
			wantUpdateRequest: cdb.GetBoolPtr(false),
		},
		{
			name: "test invalid Instance update request, name exceeded 256 char",
			fields: fields{
				Name:        cdb.GetStrPtr("apvhhigcgctlgiwtbrgldkegmnwuqcibutndlholygxvhzrpinziepszvpmopvzkybykrwgvzojtssorabkrnawgjzeuuerphsnecipubeuzrpewkfuvwoeybagaxpvjvzvbzqznyfmcpbxrhbdkhewiepykfjeejeqatswgrlhqkgnvwqmatejufnsjgelcugcoccybywdrnlyvsegsegorygwdvurgktpuzyrsoutspsnyzynliaxwseazqmimp"),
				Description: cdb.GetStrPtr("Test description"),
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance update request, description exceeded 1024 char",
			fields: fields{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("rkbfdrkybjqtrvgeqjubtkeoolyhxicmnisgpaffhdldzgciilwbwqglwglqiibcntguwihfxttrwqvyneomiqaseaxfaeblkavuskxhpbxjbzvbtdbxmrqmgekhqtbsqhgiuirtppkurmwtzemljjzajnwqaqijefyvoqufjopbkepizjurtgezlivtwkmemfdjtkdskbtqkrkcpozdwjplhszfabwhfygxonkgjgctlulkvkqzxrngzuqgrkunwcafpamvynsjtvayqdlrbafirygnlrngxhkxccowqygidzocwbnyhebvtisdimfjqnceznffsiscdshbsrdhnggyskqawlltbmidtisehwryfwmfpvisjyqgcoekxemhixvsxgrwkhlqmkhbtrcnhrdfsakumvqtggmymnomwxvxnqdlcqzlerjrvzuxhunmdilxawtuxgmsnljhdromaoelxgzfsgnhttulfqwzxvufqpoxadlbnmbtlckxgrzfirvscbpzanhrhgvrsdmkqfahfridkdlhgbjvdenhibsfjdgbaiszwyqilhslwvxtstrtmdvumdtpruduviujwytepzxzexbjnuizhpvufzcjicrlaqsvufrivvsgbcrqaztasucyjtfefbxoolzmgshhjeegmwcziqgjhninqphkvgpguquikakbljemkvbpfajumhlaiahaijvdsodklqsxorsdtiksqfhmnrutafnyqqswfmfzahwmucyhwzgxthnedcfuaptaqzylwuljaxybgyenybekgkfgmpxmkcvcmyxyazykchibcugfcwxezqcwmghjweppuisyttkaodulvgzpwfzdtstvvotulpookzpwxoyqhdzcljsguieoijbsoprtfbgzuoiiogudmjpabkfiydqyatymujnfpdhugbijaawzbohqfkvlbaojsasbyrxrapdphqmnqabpbrcowvxfwlfabbmijdabqacvpokeogjhhmoswfqulgzly"),
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test valid Instance update request, accept description as empty string",
			fields: fields{
				Name:              cdb.GetStrPtr("test-name"),
				Description:       cdb.GetStrPtr(""),
				Labels:            map[string]string{"name": "test-name", "description": ""},
				IpxeScript:        cdb.GetStrPtr("#ipxe\ndefault"),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
				InfiniBandInterfaces: []APIInfiniBandInterfaceCreateOrUpdateRequest{
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        1,
						IsPhysical:            true,
					},
				},
				SSHKeyGroupIDs:         []string{uuid.NewString()},
				NetworkSecurityGroupID: cdb.GetStrPtr(uuid.NewString()),
			},
			wantErr:           false,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test valid Instance update request ApplyUpdatesOnReboot can't be specifed",
			fields: fields{
				Name:                 cdb.GetStrPtr("test-name"),
				Description:          cdb.GetStrPtr("Test description"),
				ApplyUpdatesOnReboot: cdb.GetBoolPtr(true),
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance config update request, invalid InfiniBand Interface device instance",
			fields: fields{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("Test description"),
				InfiniBandInterfaces: []APIInfiniBandInterfaceCreateOrUpdateRequest{
					{
						InfiniBandPartitionID: uuid.NewString(),
						Device:                "MT28908 Family [ConnectX-6]",
						DeviceInstance:        -1,
						IsPhysical:            true,
					},
				},
				SSHKeyGroupIDs:         []string{uuid.NewString()},
				NetworkSecurityGroupID: cdb.GetStrPtr(uuid.NewString()),
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance config update request, invalid Interface device instance",
			fields: fields{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("Test description"),
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						VpcPrefixID:    cdb.GetStrPtr(uuid.NewString()),
						Device:         cdb.GetStrPtr("MT28908 Family [ConnectX-6]"),
						DeviceInstance: cdb.GetIntPtr(-1),
						IsPhysical:     true,
					},
				},
				SSHKeyGroupIDs:         []string{uuid.NewString()},
				NetworkSecurityGroupID: cdb.GetStrPtr(uuid.NewString()),
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance update request, NVLink Interfaces specified with device instance out of range",
			fields: fields{
				Name:        cdb.GetStrPtr("test-invalid-nvlink-interfaces-device-instance-out-of-range"),
				Description: cdb.GetStrPtr("Test description"),
				NVLinkInterfaces: []APINVLinkInterfaceCreateOrUpdateRequest{
					{
						NVLinkLogicalPartitionID: uuid.NewString(),
						DeviceInstance:           4,
					},
				},
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance update request, secondary VPCs require interfaces",
			fields: fields{
				SecondaryVpcIDs: []string{uuid.NewString()},
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
		{
			name: "test invalid Instance update request, secondary VPCs require vpcPrefix interfaces",
			fields: fields{
				SecondaryVpcIDs: []string{uuid.NewString()},
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{
						SubnetID: cdb.GetStrPtr(uuid.NewString()),
					},
				},
			},
			wantErr:           true,
			wantUpdateRequest: cdb.GetBoolPtr(true),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			itur := APIInstanceUpdateRequest{
				Name:                     tt.fields.Name,
				Description:              tt.fields.Description,
				Labels:                   tt.fields.Labels,
				TriggerReboot:            tt.fields.TriggerReboot,
				RebootWithCustomIpxe:     tt.fields.RebootWithCustomIpxe,
				ApplyUpdatesOnReboot:     tt.fields.ApplyUpdatesOnReboot,
				OperatingSystemID:        tt.fields.OperatingSystemID,
				IpxeScript:               tt.fields.IpxeScript,
				UserData:                 tt.fields.UserData,
				PhoneHomeEnabled:         tt.fields.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: tt.fields.AlwaysBootWithCustomIpxe,
				SecondaryVpcIDs:          tt.fields.SecondaryVpcIDs,
				Interfaces:               tt.fields.Interfaces,
				InfiniBandInterfaces:     tt.fields.InfiniBandInterfaces,
				NVLinkInterfaces:         tt.fields.NVLinkInterfaces,
				SSHKeyGroupIDs:           tt.fields.SSHKeyGroupIDs,
				NetworkSecurityGroupID:   tt.fields.NetworkSecurityGroupID,
			}
			err := itur.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantUpdateRequest != nil {
					assert.Equal(t, *tt.wantUpdateRequest, itur.IsUpdateRequest())
				}
			} else {
				assert.NoError(t, err)
				// Verify at least one interface is physical
				if len(itur.Interfaces) > 0 {
					assert.True(t, itur.Interfaces[0].IsPhysical)
				}
			}
		})
	}
}

func TestAPIInstanceUpdateRequest_ValidateAndSetOperatingSystemData(t *testing.T) {

	cfg1 := config.NewConfig()

	cfg1.SetSitePhoneHomeUrl("http://localhost/local")

	// iPXE OS
	osPxe := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		Type:             cdbm.OperatingSystemTypeIPXE,
		IpxeScript:       cdb.GetStrPtr("925e37ee-29b5-11ef-ba3c-8752bb7488f6"),
		UserData:         cdb.GetStrPtr("{'hostname': 'd2def8d8-29b2-11ef-81e6-07a09293ef16'}"),
		PhoneHomeEnabled: true,
		IsActive:         true,
		AllowOverride:    true,
	}

	osPxeOverrideForbidden := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		Type:             cdbm.OperatingSystemTypeIPXE,
		IpxeScript:       cdb.GetStrPtr("925e37ee-29b5-11ef-ba3c-8752bb7488f6"),
		UserData:         cdb.GetStrPtr("{'hostname': 'd2def8d8-29b2-11ef-81e6-07a09293ef16'}"),
		PhoneHomeEnabled: true,
		AllowOverride:    false,
	}

	// Image OS
	osImage := &cdbm.OperatingSystem{
		ID:            uuid.New(),
		Name:          "ab",
		Type:          cdbm.OperatingSystemTypeImage,
		UserData:      cdb.GetStrPtr("{'hostname': 'd2def8d8-29b2-11ef-81e6-07a09293ef16'}"),
		IsActive:      true,
		AllowOverride: true,
	}

	// Instance without ipxe and user-data.
	// This should be used for simulating an instance
	// that was created with either no OS specified
	// or with an OS that didn't have these values
	// set.  This is because an instance created
	// with an OS specified would have inherited these
	// values from the OS upon creation.
	instanceNoVals := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "",
		IpxeScript:               nil,
		AlwaysBootWithCustomIpxe: false,
		PhoneHomeEnabled:         false,
		UserData:                 nil,
	}

	// Instance with ipxe and user-data.
	instanceWithVals := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "",
		IpxeScript:               cdb.GetStrPtr("#!ipxe 9ea0c946-29af-11ef-b798-df4626ad0292"),
		AlwaysBootWithCustomIpxe: true,
		PhoneHomeEnabled:         true,
		UserData:                 cdb.GetStrPtr("{'hostname': '815f5bd8-29b2-11ef-b3b1-ab4be50a4e4d'}"),
	}

	tests := []struct {
		name     string
		request  *APIInstanceUpdateRequest
		cfg      *config.Config
		os       *cdbm.OperatingSystem
		instance *cdbm.Instance
		wantErr  bool
	}{
		{
			name: "os nil, ipxe not set, expect error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       nil,
			instance: instanceNoVals,
			wantErr:  true,
		},
		// If clearing the OS means _all_ overrides must be explicitly passed in, then
		// this should fail.
		{
			name: "os nil, ipxe in instance, expect failure",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
				OperatingSystemID:        cdb.GetStrPtr(""),
			},
			cfg:      cfg1,
			os:       nil,
			instance: instanceWithVals,
			wantErr:  true,
		},
		{
			name: "os image, ipxe set, expect error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               cdb.GetStrPtr("anything"),
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osImage,
			instance: instanceWithVals,
			wantErr:  true,
		},
		{
			name: "os image, no ipxe set, always boot ipxe set in req, expect error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: cdb.GetBoolPtr(true),
			},
			cfg:      cfg1,
			os:       osImage,
			instance: instanceNoVals,
			wantErr:  true,
		},
		{
			name: "os image, no ipxe set, always boot ipxe set in instance, expect error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osImage,
			instance: instanceWithVals,
			wantErr:  true,
		},
		{
			name: "os image, no ipxe set, phone home set in req, expect no error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				PhoneHomeEnabled:         cdb.GetBoolPtr(true),
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osImage,
			instance: instanceNoVals,
			wantErr:  false,
		},
		{
			name: "os image, no ipxe set, phone home set in instance, expect error",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osImage,
			instance: instanceWithVals,
			wantErr:  true,
		},
		{
			name: "OS ID nonnil, os nonnil ipxe, instance values nil, req values nil, expect success",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        cdb.GetStrPtr(uuid.NewString()),
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceNoVals,
			wantErr:  false,
		},
		{
			name: "OS ID nil, os nonnil ipxe, instance values nonnil, req values nil, expect success",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        nil,
				IpxeScript:               nil,
				PhoneHomeEnabled:         nil,
				AlwaysBootWithCustomIpxe: nil,
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceWithVals,
			wantErr:  false,
		},
		{
			name: "OS ID nil, os nonnil ipxe, instance values nil, req values nonnil, expect success",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 instanceWithVals.UserData,
				OperatingSystemID:        nil,
				IpxeScript:               instanceWithVals.IpxeScript,
				PhoneHomeEnabled:         &instanceWithVals.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: &instanceWithVals.AlwaysBootWithCustomIpxe,
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceNoVals,
			wantErr:  false,
		},
		{
			name: "OS ID nil, os nonnil ipxe, original os has user-data, override not allowed, instance values nil, req values nonnil, expect failure",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 instanceWithVals.UserData,
				OperatingSystemID:        nil,
				IpxeScript:               instanceWithVals.IpxeScript,
				PhoneHomeEnabled:         &instanceWithVals.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: &instanceWithVals.AlwaysBootWithCustomIpxe,
			},
			cfg:      cfg1,
			os:       osPxeOverrideForbidden,
			instance: instanceNoVals,
			wantErr:  true,
		},
		{
			name: "OS ID nil, os nonnil ipxe, original os has user-data, override not allowed, instance values nil, req user-data nil, expect success",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 nil,
				OperatingSystemID:        nil,
				IpxeScript:               instanceWithVals.IpxeScript,
				PhoneHomeEnabled:         &instanceWithVals.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: &instanceWithVals.AlwaysBootWithCustomIpxe,
			},
			cfg:      cfg1,
			os:       osPxeOverrideForbidden,
			instance: instanceNoVals,
			wantErr:  false,
		},
		{
			name: "OS ID nil, os nonnil ipxe, instance values nil, req values nil, expect failure",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 instanceWithVals.UserData,
				OperatingSystemID:        nil,
				IpxeScript:               nil,
				PhoneHomeEnabled:         &instanceWithVals.PhoneHomeEnabled,
				AlwaysBootWithCustomIpxe: &instanceWithVals.AlwaysBootWithCustomIpxe,
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceNoVals,
			wantErr:  true,
		},
		{
			name: "OS ID nil, os nonnil ipxe, set valid but technically empty user-data, phonehome enabled, expect failure",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 cdb.GetStrPtr("#cloud-config"),
				OperatingSystemID:        nil,
				IpxeScript:               cdb.GetStrPtr("anything"),
				PhoneHomeEnabled:         cdb.GetBoolPtr(true),
				AlwaysBootWithCustomIpxe: cdb.GetBoolPtr(false),
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceNoVals,
			wantErr:  true,
		},
		{
			name: "OS ID nil, os nonnil ipxe, set valid but technically empty user-data, phonehome disabled, expect success",
			request: &APIInstanceUpdateRequest{
				Name:                     cdb.GetStrPtr("test-name"),
				Description:              cdb.GetStrPtr("Test description"),
				UserData:                 cdb.GetStrPtr("#cloud-config"),
				OperatingSystemID:        nil,
				IpxeScript:               cdb.GetStrPtr("anything"),
				PhoneHomeEnabled:         cdb.GetBoolPtr(false),
				AlwaysBootWithCustomIpxe: cdb.GetBoolPtr(false),
			},
			cfg:      cfg1,
			os:       osPxe,
			instance: instanceNoVals,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iur := tt.request

			err := iur.ValidateAndSetOperatingSystemData(tt.cfg, tt.instance, tt.os)
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIInstanceUpdateRequest.ValidateAndSetOperatingSystemData() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
		})
	}
}

func TestAPIInstanceUpdateRequest_ValidateAndSetOperatingSystemData_Phonehome(t *testing.T) {
	cfg1 := config.NewConfig()

	cfg1.SetSitePhoneHomeUrl("http://localhost/local")

	// iPXE OS with user-data
	os1 := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr("#cloud-config\n{'hostname': 'd2def8d8-29b2-11ef-81e6-07a09293ef16'}"),
		PhoneHomeEnabled: true,
		IsActive:         true,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		AllowOverride:    true,
	}

	// Instance with ipxe and user-data.
	instance1 := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "",
		IpxeScript:               cdb.GetStrPtr("#!ipxe 9ea0c946-29af-11ef-b798-df4626ad0292"),
		AlwaysBootWithCustomIpxe: true,
		PhoneHomeEnabled:         true,
		UserData:                 cdb.GetStrPtr("#cloud-config\n{'hostname': '815f5bd8-29b2-11ef-b3b1-ab4be50a4e4d'}"),
	}

	// Instance with ipxe and user-data.
	instance2 := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "",
		IpxeScript:               cdb.GetStrPtr("#!ipxe 9ea0c946-29af-11ef-b798-df4626ad0292"),
		AlwaysBootWithCustomIpxe: true,
		PhoneHomeEnabled:         true,
	}

	// Instance with ipxe and user-data.
	instance3 := &cdbm.Instance{
		ID:                       uuid.New(),
		Name:                     "",
		IpxeScript:               cdb.GetStrPtr("#!ipxe 9ea0c946-29af-11ef-b798-df4626ad0292"),
		AlwaysBootWithCustomIpxe: true,
		PhoneHomeEnabled:         false,
	}

	tests := []struct {
		name                     string
		request                  *APIInstanceUpdateRequest
		cfg                      *config.Config
		os                       *cdbm.OperatingSystem
		userDataExactMatch       *string
		userDataSearches         []string
		userDataNegativeSearches []string
		instance                 *cdbm.Instance
		wantErr                  bool
	}{
		{
			name: "test valid Instance PhoneHome enabled update request when userData is nil when OS is nil, expect success",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				UserData:         nil,
				IpxeScript:       cdb.GetStrPtr("#!ipxe d5b692a8-29af-11ef-90ef-d392e60d87b2"),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			cfg:      cfg1,
			instance: instance1,
			wantErr:  false,
			userDataSearches: []string{
				cfg1.GetSitePhoneHomeUrl(),
				// If the instance had user-data, adn no user-data override is being sent
				// and the OS is not being cleared, we should find the instance's
				// user-data.
				"815f5bd8-29b2-11ef-b3b1-ab4be50a4e4d",
			},
		},
		{
			name: "test invalid Instance PhoneHome enabled update request when userData is invalid and OS is nil, expect failure",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				UserData:         cdb.GetStrPtr("test-user-data"),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
				IpxeScript:       cdb.GetStrPtr("#!ipxe e9d97138-29af-11ef-8b2c-57634a01308c"),
			},
			wantErr:  true,
			instance: instance1,
			cfg:      cfg1,
		},
		{
			name: "test valid Instance update request when phone home flag is disabled, userData is non-YAML and OS is nil",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				UserData:         cdb.GetStrPtr("test-user-data"),
				PhoneHomeEnabled: cdb.GetBoolPtr(false),
				IpxeScript:       cdb.GetStrPtr("#!ipxe e9d97138-29af-11ef-8b2c-57634a01308c"),
			},
			wantErr:  false,
			instance: instance1,
			cfg:      cfg1,
		},
		{
			name: "test valid Instance update request when phone home flag is unspecified, userData is non-YAML and OS is nil",
			request: &APIInstanceUpdateRequest{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("Test description"),
				UserData:    cdb.GetStrPtr("test-user-data"),
				IpxeScript:  cdb.GetStrPtr("#!ipxe e9d97138-29af-11ef-8b2c-57634a01308c"),
			},
			wantErr:  false,
			instance: instance3,
			cfg:      cfg1,
		},
		{
			name: "test valid Instance PhoneHome enabled update request when userData is valid when OS is nil",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				IpxeScript:       cdb.GetStrPtr("#!ipxe ecf9ec1c-29af-11ef-a963-8f9524fd4f22"),
				UserData:         cdb.GetStrPtr(util.TestCommonCloudInit),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			wantErr:  false,
			instance: instance1,
			cfg:      cfg1,
			userDataSearches: []string{
				"#cloud-config",
				cfg1.GetSitePhoneHomeUrl(),
			},
			userDataNegativeSearches: []string{
				"815f5bd8-29b2-11ef-b3b1-ab4be50a4e4d",
			},
		},
		{
			name: "test valid Instance PhoneHome enabled update request when OS in present with phonehome, userData doesn't contain phone home url",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				UserData:         nil,
				PhoneHomeEnabled: cdb.GetBoolPtr(false),
			},
			wantErr:  false,
			cfg:      cfg1,
			instance: instance1,
			os:       os1,
			userDataNegativeSearches: []string{
				cfg1.GetSitePhoneHomeUrl(),
			},
		},
		{
			name: "PhoneHome enabled in request, no base os change, os nonnil, expect instance user-data, expect success",
			request: &APIInstanceUpdateRequest{
				Name:             cdb.GetStrPtr("test-name"),
				Description:      cdb.GetStrPtr("Test description"),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			wantErr:  false,
			cfg:      cfg1,
			instance: instance1,
			os:       os1,
			userDataSearches: []string{
				"#cloud-config",
				cfg1.GetSitePhoneHomeUrl(),
				"815f5bd8-29b2-11ef-b3b1-ab4be50a4e4d",
			},
		},
		{
			name: "PhoneHome enabled in request, base os change, os nonnil, empty user-data, expect instance user-data, expect success",
			request: &APIInstanceUpdateRequest{
				Name:              cdb.GetStrPtr("test-name"),
				Description:       cdb.GetStrPtr("Test description"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr(""),
			},
			wantErr:            false,
			cfg:                cfg1,
			instance:           instance1,
			os:                 os1,
			userDataExactMatch: cdb.GetStrPtr(fmt.Sprintf(SitePhoneHomeCloudInit, cfg1.GetSitePhoneHomeUrl())),
		},
		{
			name: "PhoneHome enabled in instance and request updates only base OS",
			request: &APIInstanceUpdateRequest{
				Name:              cdb.GetStrPtr("test-name"),
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
			},
			wantErr:  false,
			cfg:      cfg1,
			instance: instance1,
			os:       os1,
			userDataSearches: []string{
				cfg1.GetSitePhoneHomeUrl(),
				"d2def8d8-29b2-11ef-81e6-07a09293ef16",
			},
		},
		{
			name: "PhoneHome enabled in instance and request updates only user-data",
			request: &APIInstanceUpdateRequest{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("Test description"),
				UserData:    cdb.GetStrPtr("{'hostname': '563d2b4c-29b2-11ef-ad4f-df06abe3358c'}"),
			},
			wantErr:  false,
			cfg:      cfg1,
			instance: instance1,
			os:       os1,
			userDataSearches: []string{
				cfg1.GetSitePhoneHomeUrl(),
				"563d2b4c-29b2-11ef-ad4f-df06abe3358c",
			},
		},

		{
			name: "PhoneHome enabled in instance with no user-data and request updates only user-data",
			request: &APIInstanceUpdateRequest{
				Name:        cdb.GetStrPtr("test-name"),
				Description: cdb.GetStrPtr("Test description"),
				UserData:    cdb.GetStrPtr("{'hostname': '563d2b4c-29b2-11ef-ad4f-df06abe3358c'}"),
			},
			wantErr:  false,
			cfg:      cfg1,
			instance: instance2,
			os:       os1,
			userDataSearches: []string{
				cfg1.GetSitePhoneHomeUrl(),
				"563d2b4c-29b2-11ef-ad4f-df06abe3358c",
			},
			userDataNegativeSearches: []string{
				// It should not find the value of the OS-level user-data.
				// This could be a case where the OS had user-data but it was intentionally emptied for the instance.
				"d2def8d8-29b2-11ef-81e6-07a09293ef16",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iur := tt.request

			err := iur.ValidateAndSetOperatingSystemData(tt.cfg, tt.instance, tt.os)
			if err != nil {
				if !tt.wantErr {
					assert.NoError(t, err)
				}
				return
			}

			// If phone-home is enabled, user-data can't be nil
			if iur.PhoneHomeEnabled != nil && *iur.PhoneHomeEnabled {
				assert.NotNil(t, iur.UserData)
			}

			// Even if phone-home isn't enabled, we might expect some pre-existing
			// user-data
			if tt.userDataExactMatch != nil {
				assert.Equal(t, *tt.userDataExactMatch, *iur.UserData)
			}

			for _, search := range tt.userDataSearches {
				assert.Contains(t, *iur.UserData, search)
			}

			for _, search := range tt.userDataNegativeSearches {
				assert.NotContains(t, *iur.UserData, search)
			}
		})
	}
}

func Test_getAggregatedInstanceStatus(t *testing.T) {
	type args struct {
		status      string
		powerStatus *string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test get aggregated Instance status when Instance status is not Ready",
			args: args{
				status:      cdbm.InstanceStatusPending,
				powerStatus: cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			},
			want: cdbm.InstanceStatusPending,
		},
		{
			name: "test get aggregated Instance status when Instance status is Ready and power status is Rebooting",
			args: args{
				status:      cdbm.InstanceStatusReady,
				powerStatus: cdb.GetStrPtr(cdbm.InstancePowerStatusRebooting),
			},
			want: cdbm.InstancePowerStatusRebooting,
		},
		{
			name: "test get aggregated Instance status when Instance status is Ready and power status is Error",
			args: args{
				status:      cdbm.InstanceStatusReady,
				powerStatus: cdb.GetStrPtr(cdbm.InstancePowerStatusError),
			},
			want: cdbm.InstancePowerStatusError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAggregatedInstanceStatus(tt.args.status, tt.args.powerStatus); got != tt.want {
				t.Errorf("getAggregatedInstanceStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIInstanceDeleteRequest_Validate(t *testing.T) {
	type fields struct {
		MachineHealthIssue *APIMachineHealthIssue
		IsRepairTenant     *bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test valid Instance delete request",
			fields: fields{
				MachineHealthIssue: &APIMachineHealthIssue{
					Category: "Hardware",
					Summary:  cdb.GetStrPtr("Test summary"),
					Details:  cdb.GetStrPtr("Test details"),
				},
				IsRepairTenant: cdb.GetBoolPtr(true),
			},
			wantErr: false,
		},
		{
			name: "test invalid Instance delete request - invalid machine health issue category",
			fields: fields{
				MachineHealthIssue: &APIMachineHealthIssue{
					Category: "Invalid",
				},
				IsRepairTenant: cdb.GetBoolPtr(true),
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance delete request - required machine health issue summary",
			fields: fields{
				MachineHealthIssue: &APIMachineHealthIssue{
					Category: "Hardware",
				},
				IsRepairTenant: cdb.GetBoolPtr(true),
			},
			wantErr: true,
		},
		{
			name: "test invalid Instance delete request - invalid category",
			fields: fields{
				MachineHealthIssue: &APIMachineHealthIssue{
					Category: "Storage",
					Summary:  cdb.GetStrPtr("Test summary"),
					Details:  cdb.GetStrPtr(""),
				},
				IsRepairTenant: cdb.GetBoolPtr(true),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idr := APIInstanceDeleteRequest{
				MachineHealthIssue: tt.fields.MachineHealthIssue,
			}

			err := idr.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIInstanceDeleteRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
		})
	}
}

// TestAPIInstanceCreateRequest_Validate_Auto exercises the `auto` /
// `interfaces` exclusivity rules introduced for zero-DPU instances.
func TestAPIInstanceCreateRequest_Validate_Auto(t *testing.T) {
	tests := []struct {
		name             string
		req              APIInstanceCreateRequest
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name: "auto=true with empty interfaces succeeds",
			req: APIInstanceCreateRequest{
				Name:              "auto-instance",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    cdb.GetStrPtr(uuid.NewString()),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				AutoNetwork:       true,
				Interfaces:        nil,
			},
			wantErr: false,
		},
		{
			name: "auto=true with interfaces is rejected",
			req: APIInstanceCreateRequest{
				Name:              "auto-instance",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    cdb.GetStrPtr(uuid.NewString()),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				AutoNetwork:       true,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{SubnetID: cdb.GetStrPtr(uuid.NewString())},
				},
			},
			wantErr:          true,
			wantErrorMessage: "`interfaces` must be empty when `autoNetwork` is true",
		},
		{
			name: "auto=false with empty interfaces is rejected",
			req: APIInstanceCreateRequest{
				Name:              "manual-instance",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    cdb.GetStrPtr(uuid.NewString()),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				AutoNetwork:       false,
				Interfaces:        nil,
			},
			wantErr:          true,
			wantErrorMessage: "at least one Interface must be specified",
		},
		{
			name: "auto=true with secondaryVpcIds is rejected",
			req: APIInstanceCreateRequest{
				Name:              "auto-instance",
				TenantID:          uuid.NewString(),
				InstanceTypeID:    cdb.GetStrPtr(uuid.NewString()),
				VpcID:             uuid.NewString(),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				AutoNetwork:       true,
				SecondaryVpcIDs:   []string{uuid.NewString()},
			},
			wantErr:          true,
			wantErrorMessage: "`secondaryVpcIds` is not supported when `autoNetwork` is true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}
		})
	}
}

// TestAPIBatchInstanceCreateRequest_Validate_Auto mirrors the create-side
// exclusivity rules for the batch endpoint.
func TestAPIBatchInstanceCreateRequest_Validate_Auto(t *testing.T) {
	tests := []struct {
		name             string
		req              APIBatchInstanceCreateRequest
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name: "auto=true with empty interfaces succeeds",
			req: APIBatchInstanceCreateRequest{
				NamePrefix:     "auto-batch",
				Count:          2,
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr("test ipxe"),
				AutoNetwork:    true,
			},
			wantErr: false,
		},
		{
			name: "auto=true with interfaces is rejected",
			req: APIBatchInstanceCreateRequest{
				NamePrefix:     "auto-batch",
				Count:          2,
				TenantID:       uuid.NewString(),
				InstanceTypeID: uuid.NewString(),
				VpcID:          uuid.NewString(),
				IpxeScript:     cdb.GetStrPtr("test ipxe"),
				AutoNetwork:    true,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{SubnetID: cdb.GetStrPtr(uuid.NewString())},
				},
			},
			wantErr:          true,
			wantErrorMessage: "`interfaces` must be empty when `autoNetwork` is true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}
		})
	}
}

// TestAPIInstanceUpdateRequest_Validate_Auto covers the auto/interfaces
// exclusivity rule when toggling auto via the update endpoint.
func TestAPIInstanceUpdateRequest_Validate_Auto(t *testing.T) {
	autoTrue := true
	autoFalse := false
	tests := []struct {
		name             string
		req              APIInstanceUpdateRequest
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name:    "auto unset leaves validation untouched",
			req:     APIInstanceUpdateRequest{AutoNetwork: nil},
			wantErr: false,
		},
		{
			name:    "auto=true with no interfaces succeeds",
			req:     APIInstanceUpdateRequest{AutoNetwork: &autoTrue},
			wantErr: false,
		},
		{
			name: "auto=true with interfaces is rejected",
			req: APIInstanceUpdateRequest{
				AutoNetwork: &autoTrue,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{SubnetID: cdb.GetStrPtr(uuid.NewString())},
				},
			},
			wantErr:          true,
			wantErrorMessage: "`interfaces` must be empty when `autoNetwork` is true",
		},
		{
			name: "auto=false with interfaces succeeds",
			req: APIInstanceUpdateRequest{
				AutoNetwork: &autoFalse,
				Interfaces: []APIInterfaceCreateOrUpdateRequest{
					{SubnetID: cdb.GetStrPtr(uuid.NewString())},
				},
			},
			wantErr: false,
		},
		{
			name: "auto=true with secondaryVpcIds is rejected",
			req: APIInstanceUpdateRequest{
				AutoNetwork:     &autoTrue,
				SecondaryVpcIDs: []string{uuid.NewString()},
			},
			wantErr:          true,
			wantErrorMessage: "`secondaryVpcIds` is not supported when `autoNetwork` is true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}
		})
	}
}
