// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIVpcCreateRequest_Validate(t *testing.T) {
	type fields struct {
		Name                      string
		Description               *string
		SiteID                    string
		NetworkVirtualizationType *string
		Labels                    map[string]string
		Vni                       *int
		RoutingProfile            *string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test valid VPC create request",
			fields: fields{
				Name:        "test-name",
				Description: cdb.GetStrPtr("Test description"),
				SiteID:      uuid.NewString(),
			},
			wantErr: false,
		},
		{
			name: "test valid VPC create request - invalid names are specified names exceeded 256 char",
			fields: fields{
				Name:        "apvhhigcgctlgiwtbrgldkegmnwuqcibutndlholygxvhzrpinziepszvpmopvzkybykrwgvzojtssorabkrnawgjzeuuerphsnecipubeuzrpewkfuvwoeybagaxpvjvzvbzqznyfmcpbxrhbdkhewiepykfjeejeqatswgrlhqkgnvwqmatejufnsjgelcugcoccybywdrnlyvsegsegorygwdvurgktpuzyrsoutspsnyzynliaxwseazqmimp",
				Description: cdb.GetStrPtr("Test description"),
				SiteID:      uuid.NewString(),
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - invalid Site ID",
			fields: fields{
				Name:   "test-name",
				SiteID: "invalid-uuid",
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - invalid Network Virtualization Type",
			fields: fields{
				Name:                      "test-name",
				Description:               cdb.GetStrPtr("Test description"),
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr("VPC"),
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - valid labels are specified",
			fields: fields{
				Name:   "test-name",
				SiteID: uuid.NewString(),
				Labels: map[string]string{
					"name":        "a-nv100-VPC",
					"description": "",
				},
			},
			wantErr: false,
		},
		{
			name: "test valid VPC create request - routing profile for FNN",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr(APIVpcRoutingProfileInternal),
			},
			wantErr: false,
		},
		{
			name: "test invalid VPC create request - routing profile on non-FNN VPC",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcEthernetVirtualizer),
				RoutingProfile:            cdb.GetStrPtr(APIVpcRoutingProfileInternal),
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - Flat virtualization type",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFlat),
			},
			wantErr: false,
		},
		{
			name: "test invalid VPC create request - routing profile on Flat VPC",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFlat),
				RoutingProfile:            cdb.GetStrPtr(APIVpcRoutingProfileInternal),
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - routing profile when network virtualization type is omitted",
			fields: fields{
				Name:           "test-name",
				SiteID:         uuid.NewString(),
				RoutingProfile: cdb.GetStrPtr(APIVpcRoutingProfileExternal),
			},
			wantErr: false,
		},
		{
			name: "test invalid VPC create request - routing profile too short",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr("ab"),
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - routing profile starts with non-letter",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr("1internal"),
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - routing profile contains underscore",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr("privileged_internal"),
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - routing profile is unsupported",
			fields: fields{
				Name:                      "test-name",
				SiteID:                    uuid.NewString(),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr("tenant-edge"),
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC create request - invalid VNI",
			fields: fields{
				Name:   "test-name",
				SiteID: uuid.NewString(),
				Vni:    cdb.GetIntPtr(70000),
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - invalid labels are specified key is empty",
			fields: fields{
				Name:   "test-name",
				SiteID: uuid.NewString(),
				Labels: map[string]string{
					"name": "a-nv200=VPC",
					"":     "test",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - invalid labels are specified both key and value are empty",
			fields: fields{
				Name:   "test-name",
				SiteID: uuid.NewString(),
				Labels: map[string]string{
					"name": "a-nv300=VPC",
					"":     "",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid VPC create request - invalid labels are specified key has char more than 256",
			fields: fields{
				Name:   "test-name",
				SiteID: uuid.NewString(),
				Labels: map[string]string{
					"ygsV9MoUjep1rCwbQskkF9wfMolE3oDTCcxuYSJCx9TLKepCIku9pnHfIkxCxHkb7ucbsBL4hyLqQaHoEqpTBmfoX4Un7sGvQdHGZ7nb68JJEJ3ocFAtyCMCBt66z3ldnTqp8SXXOIhNsOh35MLYQjI8557Pu6o91TsEBqyTz0yz68HHmfNgJoreHpXfeujq4cpElUXXbQ3xfFICkNyghXgFZ0MLs2o0u1Nd29aB113X5g3FKJBCskW6eBULNmeFFG61DMM37q": "a-nv300=VPC",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcr := APIVpcCreateRequest{
				Name:                      tt.fields.Name,
				Description:               tt.fields.Description,
				SiteID:                    tt.fields.SiteID,
				NetworkVirtualizationType: tt.fields.NetworkVirtualizationType,
				Labels:                    tt.fields.Labels,
				Vni:                       tt.fields.Vni,
				RoutingProfile:            tt.fields.RoutingProfile,
			}

			if err := vcr.Validate(); (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIVpcCreateRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
		})
	}
}

func TestAPIVpcUpdateRequest_Validate(t *testing.T) {
	type fields struct {
		Name        string
		Description *string
		Labels      map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test valid VPC update request",
			fields: fields{
				Name:        "test-name",
				Description: cdb.GetStrPtr("Test description"),
			},
			wantErr: false,
		},
		{
			name: "test valid VPC update request - invalid names are specified names exceeded 256 char",
			fields: fields{
				Name:        "apvhhigcgctlgiwtbrgldkegmnwuqcibutndlholygxvhzrpinziepszvpmopvzkybykrwgvzojtssorabkrnawgjzeuuerphsnecipubeuzrpewkfuvwoeybagaxpvjvzvbzqznyfmcpbxrhbdkhewiepykfjeejeqatswgrlhqkgnvwqmatejufnsjgelcugcoccybywdrnlyvsegsegorygwdvurgktpuzyrsoutspsnyzynliaxwseazqmimp",
				Description: cdb.GetStrPtr("Test description"),
			},
			wantErr: true,
		},
		{
			name: "test valid VPC update request - valid labels are specified",
			fields: fields{
				Name: "test-name",
				Labels: map[string]string{
					"name":        "a-nv100-VPC",
					"description": "",
				},
			},
			wantErr: false,
		},
		{
			name: "test valid VPC update request - invalid labels are specified key is empty",
			fields: fields{
				Name: "test-name",
				Labels: map[string]string{
					"name": "a-nv200=VPC",
					"":     "test",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid VPC update request - invalid labels are specified both key and value are empty",
			fields: fields{
				Name: "test-name",
				Labels: map[string]string{
					"name": "a-nv300=VPC",
					"":     "",
				},
			},
			wantErr: true,
		},
		{
			name: "test valid VPC update request - invalid labels are specified key has char more than 128",
			fields: fields{
				Name: "test-name",
				Labels: map[string]string{
					"morethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128charmorethan128char": "a-nv300=VPC",
					"": "",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vur := APIVpcUpdateRequest{
				Name:        &tt.fields.Name,
				Description: tt.fields.Description,
				Labels:      tt.fields.Labels,
			}

			if err := vur.Validate(); (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIVpcUpdateRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
		})
	}
}

func TestAPIVpcVirtualizationUpdateRequest_Validate(t *testing.T) {
	vpcObj1 := &cdbm.Vpc{
		ID:                        uuid.New(),
		Name:                      "test",
		Org:                       "test",
		SiteID:                    uuid.New(),
		TenantID:                  uuid.New(),
		InfrastructureProviderID:  uuid.New(),
		NetworkVirtualizationType: cdb.GetStrPtr("ETHERNET_VIRTUALIZER"),
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}

	vpcObj2 := &cdbm.Vpc{
		ID:                        uuid.New(),
		Name:                      "test1",
		Org:                       "test1",
		SiteID:                    uuid.New(),
		TenantID:                  uuid.New(),
		InfrastructureProviderID:  uuid.New(),
		NetworkVirtualizationType: cdb.GetStrPtr("FNN"),
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}

	type fields struct {
		NetworkVirtualizationType string
		inputVpc                  *cdbm.Vpc
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test valid VPC virtualization update request",
			fields: fields{
				NetworkVirtualizationType: "FNN",
				inputVpc:                  vpcObj1,
			},
			wantErr: false,
		},
		{
			name: "test invalid VPC virtualization update request - support only FNN",
			fields: fields{
				NetworkVirtualizationType: "ETHERNET_VIRTUALIZER",
				inputVpc:                  vpcObj1,
			},
			wantErr: true,
		},
		{
			name: "test invalid VPC virtualization update request - existing vpc already FNN",
			fields: fields{
				NetworkVirtualizationType: "FNN",
				inputVpc:                  vpcObj2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vvur := APIVpcVirtualizationUpdateRequest{
				NetworkVirtualizationType: tt.fields.NetworkVirtualizationType,
			}

			if err := vvur.Validate(tt.fields.inputVpc); (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIVpcVirtualizationUpdateRequest.Validate() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}
		})
	}
}

func TestNewAPIVpc(t *testing.T) {
	type args struct {
		dbVpc cdbm.Vpc
		dbsds []cdbm.StatusDetail
	}

	dbVpc := cdbm.Vpc{
		ID:                        uuid.New(),
		Name:                      "test-vpc",
		Description:               cdb.GetStrPtr("Test VPC Description"),
		Org:                       "test-org",
		TenantID:                  uuid.New(),
		SiteID:                    uuid.New(),
		NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcEthernetVirtualizer),
		RoutingProfile:            cdb.GetStrPtr(apiVpcRoutingProfileSiteInternal),
		ControllerVpcID:           cdb.GetUUIDPtr(uuid.New()),
		// The normal expectation is that Vni and ActiveVni match or
		// that Vni is simply null, but we want to test for correctness
		// in the conversion from the record in the DB and the API struct.
		Vni:       cdb.GetIntPtr(555),
		ActiveVni: cdb.GetIntPtr(777),
		Labels: map[string]string{
			"zone": "1",
			"west": "2",
		},
		Status:  cdbm.SiteStatusPending,
		Created: time.Now(),
		Updated: time.Now(),
	}

	dbsds := []cdbm.StatusDetail{
		{
			ID:      uuid.New(),
			Status:  cdbm.SiteStatusPending,
			Created: time.Now(),
			Updated: time.Now(),
		},
	}

	apidbsh := []APIStatusDetail{}
	for _, dbsd := range dbsds {
		apidbsh = append(apidbsh, NewAPIStatusDetail(dbsd))
	}

	tests := []struct {
		name string
		args args
		want APIVpc
	}{
		{
			name: "get new APIVpc returns stored routing profile",
			args: args{
				dbVpc: dbVpc,
				dbsds: dbsds,
			},
			want: APIVpc{
				ID:                        dbVpc.ID.String(),
				Name:                      dbVpc.Name,
				Description:               dbVpc.Description,
				Org:                       dbVpc.Org,
				InfrastructureProviderID:  util.GetUUIDPtrToStrPtr(&dbVpc.InfrastructureProviderID),
				TenantID:                  util.GetUUIDPtrToStrPtr(&dbVpc.TenantID),
				SiteID:                    util.GetUUIDPtrToStrPtr(&dbVpc.SiteID),
				NetworkVirtualizationType: dbVpc.NetworkVirtualizationType,
				RoutingProfile:            cdb.GetStrPtr(APIVpcRoutingProfileInternal),
				ControllerVpcID:           util.GetUUIDPtrToStrPtr(dbVpc.ControllerVpcID),
				RequestedVni:              dbVpc.Vni,
				Vni:                       dbVpc.ActiveVni,
				Status:                    dbVpc.Status,
				Labels: map[string]string{
					"zone": "1",
					"west": "2",
				},
				StatusHistory: apidbsh,
				Created:       dbVpc.Created,
				Updated:       dbVpc.Updated,
			},
		},
		{
			name: "get new APIVpc includes routing profile for FNN VPC",
			args: args{
				dbVpc: func() cdbm.Vpc {
					fnnVpc := dbVpc
					fnnVpc.NetworkVirtualizationType = cdb.GetStrPtr(cdbm.VpcFNN)
					return fnnVpc
				}(),
				dbsds: dbsds,
			},
			want: APIVpc{
				ID:                        dbVpc.ID.String(),
				Name:                      dbVpc.Name,
				Description:               dbVpc.Description,
				Org:                       dbVpc.Org,
				InfrastructureProviderID:  util.GetUUIDPtrToStrPtr(&dbVpc.InfrastructureProviderID),
				TenantID:                  util.GetUUIDPtrToStrPtr(&dbVpc.TenantID),
				SiteID:                    util.GetUUIDPtrToStrPtr(&dbVpc.SiteID),
				NetworkVirtualizationType: cdb.GetStrPtr(cdbm.VpcFNN),
				RoutingProfile:            cdb.GetStrPtr(APIVpcRoutingProfileInternal),
				ControllerVpcID:           util.GetUUIDPtrToStrPtr(dbVpc.ControllerVpcID),
				RequestedVni:              dbVpc.Vni,
				Vni:                       dbVpc.ActiveVni,
				Status:                    dbVpc.Status,
				Labels: map[string]string{
					"zone": "1",
					"west": "2",
				},
				StatusHistory: apidbsh,
				Created:       dbVpc.Created,
				Updated:       dbVpc.Updated,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAPIVpc(tt.args.dbVpc, tt.args.dbsds)

			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Description, got.Description)
			assert.Equal(t, tt.want.Org, got.Org)
			assert.Equal(t, *tt.want.InfrastructureProviderID, *got.InfrastructureProviderID)
			assert.Equal(t, *tt.want.TenantID, *got.TenantID)
			assert.Equal(t, *tt.want.SiteID, *got.SiteID)
			assert.Equal(t, tt.want.NetworkVirtualizationType, got.NetworkVirtualizationType)
			assert.Equal(t, tt.want.RoutingProfile, got.RoutingProfile)
			assert.Equal(t, *tt.want.ControllerVpcID, *got.ControllerVpcID)
			if tt.want.Vni != nil {
				assert.NotNil(t, got.Vni)
				assert.Equal(t, *tt.want.Vni, *got.Vni)
			}
			if tt.want.RequestedVni != nil {
				assert.NotNil(t, got.RequestedVni)
				assert.Equal(t, *tt.want.RequestedVni, *got.RequestedVni)
			}
			assert.Equal(t, len(tt.want.Labels), len(got.Labels))
			assert.Equal(t, tt.want.Status, got.Status)
			assert.Equal(t, tt.want.StatusHistory, got.StatusHistory)
			assert.Equal(t, tt.want.Created, got.Created)
			assert.Equal(t, tt.want.Updated, got.Updated)
		})
	}
}

func TestAPIVpcCreateRequest_ToProto(t *testing.T) {
	id := uuid.New()
	desc := "primary"
	nsg := "nsg-1"
	nvllpID := uuid.New()
	fnn := cdbm.VpcFNN
	eth := cdbm.VpcEthernetVirtualizer

	t.Run("populates id, metadata, NSG, NVLink, and create-specific fields", func(t *testing.T) {
		profile := apiVpcRoutingProfileSiteInternal
		vpc := &cdbm.Vpc{
			ID:                        id,
			Org:                       "org-1",
			Name:                      "vpc-a",
			Description:               &desc,
			NetworkSecurityGroupID:    &nsg,
			NVLinkLogicalPartitionID:  &nvllpID,
			NetworkVirtualizationType: &fnn,
			RoutingProfile:            &profile,
			Labels:                    map[string]string{"env": "prod"},
		}
		vni := 4242
		got := APIVpcCreateRequest{
			Vni:            &vni,
			RoutingProfile: cdb.GetStrPtr(APIVpcRoutingProfileInternal),
		}.ToProto(vpc)

		require.NotNil(t, got)
		require.NotNil(t, got.Id)
		assert.Equal(t, id.String(), got.Id.Value)
		assert.Equal(t, "vpc-a", got.Name)
		assert.Equal(t, "org-1", got.TenantOrganizationId)
		require.NotNil(t, got.NetworkVirtualizationType)
		assert.Equal(t, cwssaws.VpcVirtualizationType_FNN, *got.NetworkVirtualizationType)
		require.NotNil(t, got.RoutingProfileType)
		assert.Equal(t, apiVpcRoutingProfileSiteInternal, *got.RoutingProfileType)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "nsg-1", *got.NetworkSecurityGroupId)
		require.NotNil(t, got.Vni)
		assert.Equal(t, uint32(4242), *got.Vni)
		require.NotNil(t, got.Metadata)
		assert.Equal(t, "vpc-a", got.Metadata.Name)
		assert.Equal(t, "primary", got.Metadata.Description)
		require.NotNil(t, got.DefaultNvlinkLogicalPartitionId)
		assert.Equal(t, nvllpID.String(), got.DefaultNvlinkLogicalPartitionId.Value)
	})

	t.Run("derives ETHERNET_VIRTUALIZER from the entity's DB column", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Org: "org-1", Name: "vpc-a", NetworkVirtualizationType: &eth}
		got := APIVpcCreateRequest{}.ToProto(vpc)
		require.NotNil(t, got.NetworkVirtualizationType)
		assert.Equal(t, cwssaws.VpcVirtualizationType_ETHERNET_VIRTUALIZER, *got.NetworkVirtualizationType)
	})

	t.Run("omits NetworkVirtualizationType when the entity has none", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Org: "org-1", Name: "vpc-a"}
		got := APIVpcCreateRequest{}.ToProto(vpc)
		assert.Nil(t, got.NetworkVirtualizationType)
		assert.Nil(t, got.RoutingProfileType)
		assert.Nil(t, got.Vni)
		assert.Nil(t, got.NetworkSecurityGroupId)
		assert.Nil(t, got.DefaultNvlinkLogicalPartitionId)
	})

	t.Run("nil request RoutingProfile leaves the wire field unset even if the entity carries one", func(t *testing.T) {
		// The wire follows the API request shape: if the caller did
		// not ask for a routingProfile, we don't echo a stale entity
		// value into the create request.
		profile := apiVpcRoutingProfileSiteInternal
		vpc := &cdbm.Vpc{ID: id, Org: "org-1", Name: "vpc-a", NetworkVirtualizationType: &fnn, RoutingProfile: &profile}
		got := APIVpcCreateRequest{}.ToProto(vpc)
		assert.Nil(t, got.RoutingProfileType)
	})
}

func TestAPIVpcUpdateRequest_ToProto(t *testing.T) {
	id := uuid.New()
	desc := "primary"
	nsg := "nsg-1"
	other := "nsg-other"
	empty := ""
	nvllpID := uuid.New()

	t.Run("populates id, metadata, and NSG from the merged-into-DB vpc", func(t *testing.T) {
		vpc := &cdbm.Vpc{
			ID:                     id,
			Name:                   "vpc-a",
			Description:            &desc,
			NetworkSecurityGroupID: &nsg,
			Labels:                 map[string]string{"env": "prod"},
		}
		got := APIVpcUpdateRequest{}.ToProto(vpc)
		require.NotNil(t, got)
		require.NotNil(t, got.Id)
		assert.Equal(t, id.String(), got.Id.Value)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "nsg-1", *got.NetworkSecurityGroupId)
		require.NotNil(t, got.Metadata)
		assert.Equal(t, "vpc-a", got.Metadata.Name)
		assert.Equal(t, "primary", got.Metadata.Description)
		require.Len(t, got.Metadata.Labels, 1)
		assert.Nil(t, got.DefaultNvlinkLogicalPartitionId)
	})

	t.Run("falls back to entity NSG when request did not touch the field", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a", NetworkSecurityGroupID: &nsg}
		got := APIVpcUpdateRequest{}.ToProto(vpc)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "nsg-1", *got.NetworkSecurityGroupId)
	})

	t.Run("preserves explicit NSG detach (request nil-vs-empty distinction)", func(t *testing.T) {
		// Simulates the handler path: handler cleared the DB row, so
		// vpc.NetworkSecurityGroupID is now nil, but the API request
		// carried &"" — the wire must reflect the detach intent.
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a", NetworkSecurityGroupID: nil}
		got := APIVpcUpdateRequest{NetworkSecurityGroupID: &empty}.ToProto(vpc)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "", *got.NetworkSecurityGroupId)
	})

	t.Run("API-request NSG overrides the entity-derived value", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a", NetworkSecurityGroupID: &nsg}
		got := APIVpcUpdateRequest{NetworkSecurityGroupID: &other}.ToProto(vpc)
		require.NotNil(t, got.NetworkSecurityGroupId)
		assert.Equal(t, "nsg-other", *got.NetworkSecurityGroupId)
	})

	t.Run("explicit NVLink detach sends empty value on the wire", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a", NVLinkLogicalPartitionID: nil}
		got := APIVpcUpdateRequest{NVLinkLogicalPartitionID: &empty}.ToProto(vpc)
		require.NotNil(t, got.DefaultNvlinkLogicalPartitionId)
		assert.Equal(t, "", got.DefaultNvlinkLogicalPartitionId.Value)
	})

	t.Run("NVLink override sends the entity-resolved partition ID", func(t *testing.T) {
		nvllpStr := nvllpID.String()
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a", NVLinkLogicalPartitionID: &nvllpID}
		got := APIVpcUpdateRequest{NVLinkLogicalPartitionID: &nvllpStr}.ToProto(vpc)
		require.NotNil(t, got.DefaultNvlinkLogicalPartitionId)
		assert.Equal(t, nvllpID.String(), got.DefaultNvlinkLogicalPartitionId.Value)
	})

	t.Run("omits NVLink when neither request nor entity carry it", func(t *testing.T) {
		vpc := &cdbm.Vpc{ID: id, Name: "vpc-a"}
		got := APIVpcUpdateRequest{}.ToProto(vpc)
		assert.Nil(t, got.DefaultNvlinkLogicalPartitionId)
	})

	t.Run("uses ControllerVpcID for the request Id when set", func(t *testing.T) {
		ctrlID := uuid.New()
		vpc := &cdbm.Vpc{ID: id, ControllerVpcID: &ctrlID, Name: "vpc-a"}
		got := APIVpcUpdateRequest{}.ToProto(vpc)
		require.NotNil(t, got.Id)
		assert.Equal(t, ctrlID.String(), got.Id.Value)
	})
}
