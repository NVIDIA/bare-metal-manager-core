// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"

	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/rs/zerolog/log"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

var (
	// DefaultPort is the default port that the server listens at
	DefaultPort = ":11079"
	// DefaultVpcId is the default VPC ID for testing
	DefaultVpcId = "00000000-0000-4000-8000-000000000000"
	// DefaultNetworkSegmentId is the default NetworkSegment ID for testing
	DefaultNetworkSegmentId = "00000000-0000-4000-9000-000000000000"
	// DefaultTenantKeysetId is the default TenantKeyset ID for testing
	DefaultTenantKeysetId = "00000000-0000-4000-a000-000000000000"
	// DefaultIBParitionId is the default IBPartition ID for testing
	DefaultIBParitionId = "00000000-0000-4000-b000-000000000000"
)

// NICoServerImpl implements interface NICoServer
type NICoServerImpl struct {
	cwssaws.UnimplementedForgeServer
	v   map[string]*cwssaws.Vpc
	ns  map[string]*cwssaws.NetworkSegment
	ins map[string]*cwssaws.Instance
	m   map[string]*cwssaws.Machine
	tk  map[string]*cwssaws.TenantKeyset
	ibp map[string]*cwssaws.IBPartition
	em  map[string]*cwssaws.ExpectedMachine
	eps map[string]*cwssaws.ExpectedPowerShelf
	es  map[string]*cwssaws.ExpectedSwitch
	er  map[string]*cwssaws.ExpectedRack

	// Per-org machine identity state.
	identityState    map[string]*identityOrgState
	tokenDelegations map[string]*cwssaws.TokenDelegationResponse
}

// identityKeyMaterial is a per-org ES256 keypair plus its derived kid.
type identityKeyMaterial struct {
	privateKey *ecdsa.PrivateKey
	publicPEM  string
	kid        string
}

type identityOrgState struct {
	cfg                  *cwssaws.TenantIdentityConfigResponse
	slot1                *identityKeyMaterial
	slot2                *identityKeyMaterial
	currentSlot          int
	nonActiveSlotExpires *time.Time
}

func (s *identityOrgState) inactiveSlot() int {
	if s.currentSlot == 1 {
		return 2
	}
	return 1
}

func (s *identityOrgState) activeKey() *identityKeyMaterial {
	if s.currentSlot == 1 {
		return s.slot1
	}
	return s.slot2
}

func (s *identityOrgState) inactiveKey() *identityKeyMaterial {
	if s.currentSlot == 1 {
		return s.slot2
	}
	return s.slot1
}

func (s *identityOrgState) setSlot(n int, km *identityKeyMaterial) {
	if n == 1 {
		s.slot1 = km
	} else {
		s.slot2 = km
	}
}

func (s *identityOrgState) clearInactiveSlot() {
	if s.currentSlot == 1 {
		s.slot2 = nil
	} else {
		s.slot1 = nil
	}
	s.nonActiveSlotExpires = nil
}

func (f *NICoServerImpl) gcExpiredNonActiveSigningKey(orgID string) {
	st, ok := f.identityState[orgID]
	if !ok || st.nonActiveSlotExpires == nil {
		return
	}
	if !time.Now().Before(*st.nonActiveSlotExpires) {
		st.clearInactiveSlot()
	}
}

func tenantIdentitySigningKeysResponse(st *identityOrgState) []*cwssaws.TenantIdentitySigningKey {
	if st == nil {
		return nil
	}
	var entries []*cwssaws.TenantIdentitySigningKey
	if active := st.activeKey(); active != nil {
		entries = append(entries, &cwssaws.TenantIdentitySigningKey{
			Kid:           active.kid,
			Alg:           "ES256",
			CurrentSigner: true,
		})
	}
	if inactive := st.inactiveKey(); inactive != nil {
		entry := &cwssaws.TenantIdentitySigningKey{
			Kid:           inactive.kid,
			Alg:           "ES256",
			CurrentSigner: false,
		}
		if st.nonActiveSlotExpires != nil {
			entry.ExpireAt = timestamppb.New(*st.nonActiveSlotExpires)
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].GetKid() < entries[j].GetKid()
	})
	return entries
}

var logger = log.With().Str("Component", "Mock NICo gRPC Server").Logger()

// Version implements interface NICoServer
func (f *NICoServerImpl) Version(ctx context.Context, req *cwssaws.VersionRequest) (*cwssaws.BuildInfo, error) {
	return &cwssaws.BuildInfo{
		BuildVersion: "1.0.0",
	}, nil
}

// CreateVpc implements interface NICoServer
func (f *NICoServerImpl) CreateVpc(c context.Context, req *cwssaws.VpcCreationRequest) (*cwssaws.Vpc, error) {
	if req == nil || req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nid := DefaultVpcId
	_, ok := f.v[DefaultVpcId]
	if ok {
		// Default VPC already exists, create a new one with a different ID
		nid = uuid.NewString()
	}

	nv := &cwssaws.Vpc{
		Id:                   &cwssaws.VpcId{Value: nid},
		Name:                 req.Name,
		TenantOrganizationId: req.TenantOrganizationId,
	}
	f.v[nid] = nv

	return nv, nil
}

// UpdateVpc implements interface NICoServer
func (f *NICoServerImpl) UpdateVpc(c context.Context, req *cwssaws.VpcUpdateRequest) (*cwssaws.VpcUpdateResult, error) {
	if req == nil || req.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nv, ok := f.v[req.Id.Value]
	if ok {
		if req.Name != "" {
			nv.Name = req.Name
		}
		return &cwssaws.VpcUpdateResult{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "VPC with ID %q not found", req.Id.Value)
}

// DeleteVpc implements interface NICoServer
func (f *NICoServerImpl) DeleteVpc(c context.Context, req *cwssaws.VpcDeletionRequest) (*cwssaws.VpcDeletionResult, error) {
	if req == nil || req.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	_, ok := f.v[req.Id.Value]
	if ok {
		delete(f.v, req.Id.Value)
		return &cwssaws.VpcDeletionResult{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "VPC with ID %q not found", req.Id.Value)
}

// FindVpcIds implements interface NICoServer
func (f *NICoServerImpl) FindVpcIds(ctx context.Context, req *cwssaws.VpcSearchFilter) (*cwssaws.VpcIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.VpcIdList{}
	for id := range f.v {
		response.VpcIds = append(response.VpcIds, &cwssaws.VpcId{Value: id})
	}
	return &response, nil
}

// FindVpcsByIds implements interface NICoServer
func (f *NICoServerImpl) FindVpcsByIds(ctx context.Context, req *cwssaws.VpcsByIdsRequest) (*cwssaws.VpcList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.VpcList{}
	for _, id := range req.VpcIds {
		if obj, ok := f.v[id.GetValue()]; ok {
			response.Vpcs = append(response.Vpcs, obj)
		}
	}
	return &response, nil
}

// FindVpcs implements interface NICoServer
func (f *NICoServerImpl) FindVpcs(c context.Context, req *cwssaws.VpcSearchQuery) (*cwssaws.VpcList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	res := []*cwssaws.Vpc{}

	for _, v := range f.v {
		res = append(res, v)
	}

	if req.Id != nil && req.Id.Value != "" {
		v, ok := f.v[req.Id.Value]
		if ok {
			res = []*cwssaws.Vpc{v}
		} else {
			res = []*cwssaws.Vpc{}
		}
	}

	if req.Name != nil {
		filtered := []*cwssaws.Vpc{}
		for _, nv := range f.v {
			if nv.Name == *req.Name {
				filtered = append(filtered, nv)
			}
		}
		res = filtered
	}

	return &cwssaws.VpcList{Vpcs: res}, nil
}

// CreateNetworkSegment implements interface NICoServer
func (f *NICoServerImpl) CreateNetworkSegment(c context.Context, req *cwssaws.NetworkSegmentCreationRequest) (*cwssaws.NetworkSegment, error) {
	if req == nil || req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nid := DefaultNetworkSegmentId
	_, ok := f.ns[DefaultNetworkSegmentId]
	if ok {
		// Default Network Segment already exists, create a new one with a different ID
		nid = uuid.NewString()
	}

	nns := &cwssaws.NetworkSegment{
		Id:          &cwssaws.NetworkSegmentId{Value: nid},
		Name:        req.Name,
		VpcId:       req.VpcId,
		SubdomainId: req.SubdomainId,
		Mtu:         req.Mtu,
		Prefixes:    req.Prefixes,
	}
	f.ns[nid] = nns

	return nns, nil
}

// DeleteNetworkSegment implements interface NICoServer
func (f *NICoServerImpl) DeleteNetworkSegment(c context.Context, req *cwssaws.NetworkSegmentDeletionRequest) (*cwssaws.NetworkSegmentDeletionResult, error) {
	if req == nil || req.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	_, ok := f.ns[req.Id.Value]

	if ok {
		delete(f.ns, req.Id.Value)
		return &cwssaws.NetworkSegmentDeletionResult{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "NetworkSegment with ID %q not found", req.Id.Value)
}

// FindNetworkSegmentIds implements interface NICoServer
func (f *NICoServerImpl) FindNetworkSegmentIds(ctx context.Context, req *cwssaws.NetworkSegmentSearchFilter) (*cwssaws.NetworkSegmentIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.NetworkSegmentIdList{}
	for id := range f.ns {
		response.NetworkSegmentsIds = append(response.NetworkSegmentsIds, &cwssaws.NetworkSegmentId{Value: id})
	}
	return &response, nil
}

// FindNetworkSegmentsByIds implements interface NICoServer
func (f *NICoServerImpl) FindNetworkSegmentsByIds(ctx context.Context, req *cwssaws.NetworkSegmentsByIdsRequest) (*cwssaws.NetworkSegmentList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.NetworkSegmentList{}
	for _, id := range req.NetworkSegmentsIds {
		if obj, ok := f.ns[id.GetValue()]; ok {
			response.NetworkSegments = append(response.NetworkSegments, obj)
		}
	}
	return &response, nil
}

// CreateInstance implements interface NICoServer
func (f *NICoServerImpl) AllocateInstance(ctx context.Context, req *cwssaws.InstanceAllocationRequest) (*cwssaws.Instance, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nid := uuid.NewString()
	if req.InstanceId != nil {
		nid = req.InstanceId.Value
	}

	_, ok := f.ins[nid]
	if !ok {
		ifcsts := []*cwssaws.InstanceInterfaceStatus{}
		for _, ifcreq := range req.Config.Network.Interfaces {
			ifcst := &cwssaws.InstanceInterfaceStatus{
				MacAddress: getStrPtr(generateMacAddress()),
				Addresses: []string{
					generateIPAddress(),
				},
			}
			if ifcreq.FunctionType == cwssaws.InterfaceFunctionType_VIRTUAL_FUNCTION {
				vfid := uint32(generateInteger(16))
				ifcst.VirtualFunctionId = &vfid
			}
			ifcsts = append(ifcsts, ifcst)
		}

		nins := cwssaws.Instance{
			Id:        &cwssaws.InstanceId{Value: nid},
			MachineId: req.MachineId,
			Config:    req.Config,
			Status: &cwssaws.InstanceStatus{
				Tenant: &cwssaws.InstanceTenantStatus{
					State: cwssaws.TenantState_PROVISIONING,
				},
				Network: &cwssaws.InstanceNetworkStatus{
					Interfaces: ifcsts,
				},
			},
		}

		f.ins[nid] = &nins

		m := cwssaws.Machine{
			Id:    req.MachineId,
			State: "Ready",
		}

		_, ok := f.m[req.MachineId.Id]
		if !ok {
			f.m[req.MachineId.Id] = &m
		}

		return &nins, nil
	}

	return nil, status.Errorf(codes.Internal, "Failed to create Instance")
}

// DeleteInstance implements interface NICoServer
func (f *NICoServerImpl) ReleaseInstance(c context.Context, req *cwssaws.InstanceReleaseRequest) (*cwssaws.InstanceReleaseResult, error) {
	if req == nil || req.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	_, ok := f.ins[req.Id.Value]
	if ok {
		delete(f.ins, req.Id.Value)
		return &cwssaws.InstanceReleaseResult{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "Instance with ID %q not found", req.Id.Value)
}

// FindInstances implements interface NICoServer
func (f *NICoServerImpl) FindInstanceIds(ctx context.Context, req *cwssaws.InstanceSearchFilter) (*cwssaws.InstanceIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.InstanceIdList{}
	for id := range f.ins {
		response.InstanceIds = append(response.InstanceIds, &cwssaws.InstanceId{Value: id})
	}
	return &response, nil
}

// FindInstances implements interface NICoServer
func (f *NICoServerImpl) FindInstancesByIds(ctx context.Context, req *cwssaws.InstancesByIdsRequest) (*cwssaws.InstanceList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.InstanceList{}
	for _, id := range req.InstanceIds {
		if obj, ok := f.ins[id.GetValue()]; ok {
			response.Instances = append(response.Instances, obj)
		}
	}
	return &response, nil
}

// InvokeInstancePower implements interface NICoServer
func (f *NICoServerImpl) InvokeInstancePower(c context.Context, req *cwssaws.InstancePowerRequest) (*cwssaws.InstancePowerResult, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	_, ok := f.m[req.MachineId.Id]
	if ok {
		if req.Operation == cwssaws.InstancePowerRequest_POWER_RESET {
			return &cwssaws.InstancePowerResult{}, nil
		}

		return &cwssaws.InstancePowerResult{}, status.Errorf(codes.InvalidArgument, "Invalid operation in request")
	}

	return nil, status.Errorf(codes.NotFound, "Machine with ID %q not found", req.MachineId.Id)
}

func (f *NICoServerImpl) FindMachineIds(ctx context.Context, req *cwssaws.MachineSearchConfig) (*cwssaws.MachineIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.MachineIdList{}
	for id := range f.m {
		response.MachineIds = append(response.MachineIds, &cwssaws.MachineId{Id: id})
	}

	return &response, nil
}

func (f *NICoServerImpl) SetMaintenance(context.Context, *cwssaws.MaintenanceRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// CreateTenantKeyset implements interface NICoServer
func (f *NICoServerImpl) CreateTenantKeyset(c context.Context, req *cwssaws.CreateTenantKeysetRequest) (*cwssaws.CreateTenantKeysetResponse, error) {
	if req == nil || req.KeysetIdentifier == nil || req.KeysetIdentifier.KeysetId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nid := DefaultTenantKeysetId
	_, ok := f.tk[DefaultTenantKeysetId]
	if ok {
		// Default TenantKeyset already exists, create a new one with a different ID
		nid = uuid.NewString()
	}

	ntk := &cwssaws.TenantKeyset{
		KeysetIdentifier: &cwssaws.TenantKeysetIdentifier{
			KeysetId: nid,
		},
		KeysetContent: req.KeysetContent,
		Version:       req.Version,
	}

	f.tk[nid] = ntk

	result := &cwssaws.CreateTenantKeysetResponse{
		Keyset: ntk,
	}

	return result, nil
}

// UpdateTenantKeyset implements interface NICoServer
func (f *NICoServerImpl) UpdateTenantKeyset(c context.Context, req *cwssaws.UpdateTenantKeysetRequest) (*cwssaws.UpdateTenantKeysetResponse, error) {
	if req == nil || req.KeysetIdentifier == nil || req.KeysetIdentifier.KeysetId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	eid := req.KeysetIdentifier.KeysetId

	_, ok := f.tk[eid]
	if ok {
		f.tk[eid].KeysetContent = req.KeysetContent
		f.tk[eid].Version = req.Version

		return &cwssaws.UpdateTenantKeysetResponse{}, nil
	}

	return nil, status.Errorf(codes.Internal, "TenantKeyset with ID not found")
}

// DeleteTenantKeyset implements interface NICoServer
func (f *NICoServerImpl) DeleteTenantKeyset(c context.Context, req *cwssaws.DeleteTenantKeysetRequest) (*cwssaws.DeleteTenantKeysetResponse, error) {
	if req == nil || req.KeysetIdentifier == nil || req.KeysetIdentifier.KeysetId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	eid := req.KeysetIdentifier.KeysetId

	_, ok := f.tk[eid]
	if ok {
		delete(f.tk, eid)
		return &cwssaws.DeleteTenantKeysetResponse{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "TenantKeyset with ID %q not found", eid)
}

// FindTenantKeysetIds implements interface NICoServer
func (f *NICoServerImpl) FindTenantKeysetIds(ctx context.Context, req *cwssaws.TenantKeysetSearchFilter) (*cwssaws.TenantKeysetIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.TenantKeysetIdList{}
	for id := range f.tk {
		response.KeysetIds = append(response.KeysetIds, &cwssaws.TenantKeysetIdentifier{KeysetId: id})
	}
	return &response, nil
}

// FindTenantKeysetsByIds implements interface NICoServer
func (f *NICoServerImpl) FindTenantKeysetsByIds(ctx context.Context, req *cwssaws.TenantKeysetsByIdsRequest) (*cwssaws.TenantKeySetList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.TenantKeySetList{}
	for _, id := range req.KeysetIds {
		if obj, ok := f.tk[id.KeysetId]; ok {
			response.Keyset = append(response.Keyset, obj)
		}
	}
	return &response, nil
}

// CreateIBPartition implements interface NICoServer
func (f *NICoServerImpl) CreateIBPartition(c context.Context, req *cwssaws.IBPartitionCreationRequest) (*cwssaws.IBPartition, error) {
	if req == nil || req.Config == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	nid := DefaultIBParitionId
	_, ok := f.ibp[DefaultNetworkSegmentId]
	if ok {
		// Default IBPartition already exists, create a new one with a different ID
		nid = uuid.NewString()
	}

	nibp := &cwssaws.IBPartition{
		Id: &cwssaws.IBPartitionId{Value: nid},
		Config: &cwssaws.IBPartitionConfig{
			Name:                 req.Config.Name,
			TenantOrganizationId: req.Config.TenantOrganizationId,
		},
	}

	f.ibp[nid] = nibp
	return nibp, nil
}

// UpdateIBPartition implements interface NICoServer
func (f *NICoServerImpl) UpdateIBPartition(c context.Context, req *cwssaws.IBPartitionUpdateRequest) (*cwssaws.IBPartition, error) {
	if req == nil || req.Id == nil || req.Id.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	ibp, ok := f.ibp[req.Id.Value]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "IB Partition with ID %q not found", req.Id.Value)
	}
	if req.Config != nil {
		if ibp.Config == nil {
			ibp.Config = &cwssaws.IBPartitionConfig{}
		}
		if req.Config.Name != "" {
			ibp.Config.Name = req.Config.Name
		}
		if req.Config.TenantOrganizationId != "" {
			ibp.Config.TenantOrganizationId = req.Config.TenantOrganizationId
		}
		if req.Config.Pkey != nil {
			ibp.Config.Pkey = req.Config.Pkey
		}
	}
	if req.Metadata != nil {
		ibp.Metadata = req.Metadata
	}
	return ibp, nil
}

// DeleteIBPartition implements interface NICoServer
func (f *NICoServerImpl) DeleteIBPartition(c context.Context, req *cwssaws.IBPartitionDeletionRequest) (*cwssaws.IBPartitionDeletionResult, error) {
	if req == nil || req.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}

	_, ok := f.ibp[req.Id.Value]

	if ok {
		delete(f.ibp, req.Id.Value)
		return &cwssaws.IBPartitionDeletionResult{}, nil
	}

	return nil, status.Errorf(codes.NotFound, "IB Partition with ID %q not found", req.Id.Value)
}

// FindIBPartitionIds implements interface NICoServer
func (f *NICoServerImpl) FindIBPartitionIds(ctx context.Context, req *cwssaws.IBPartitionSearchFilter) (*cwssaws.IBPartitionIdList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.IBPartitionIdList{}
	for id := range f.ibp {
		response.IbPartitionIds = append(response.IbPartitionIds, &cwssaws.IBPartitionId{Value: id})
	}
	return &response, nil
}

// FindIBPartitionsByIds implements interface NICoServer
func (f *NICoServerImpl) FindIBPartitionsByIds(ctx context.Context, req *cwssaws.IBPartitionsByIdsRequest) (*cwssaws.IBPartitionList, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	response := cwssaws.IBPartitionList{}
	for _, id := range req.IbPartitionIds {
		if obj, ok := f.ibp[id.GetValue()]; ok {
			response.IbPartitions = append(response.IbPartitions, obj)
		}
	}
	return &response, nil
}

// AddExpectedMachine implements interface NICoServer
func (f *NICoServerImpl) AddExpectedMachine(ctx context.Context, req *cwssaws.ExpectedMachine) (*emptypb.Empty, error) {
	if req == nil || req.Id == nil || req.Id.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for AddExpectedMachine")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for AddExpectedMachine")
	}
	if req.ChassisSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Chassis Serial Number not provided for AddExpectedMachine")
	}
	f.em[req.Id.Value] = req
	return &emptypb.Empty{}, nil
}

// UpdateExpectedMachine implements interface NICoServer
func (f *NICoServerImpl) UpdateExpectedMachine(ctx context.Context, req *cwssaws.ExpectedMachine) (*emptypb.Empty, error) {
	if req == nil || req.Id == nil || req.Id.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for UpdateExpectedMachine")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for UpdateExpectedMachine")
	}
	if req.ChassisSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Chassis Serial Number not provided for UpdateExpectedMachine")
	}
	if _, ok := f.em[req.Id.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedMachine with ID %q not found", req.Id.Value)
	}
	f.em[req.Id.Value] = req
	return &emptypb.Empty{}, nil
}

// DeleteExpectedMachine implements interface NICoServer
func (f *NICoServerImpl) DeleteExpectedMachine(ctx context.Context, req *cwssaws.ExpectedMachineRequest) (*emptypb.Empty, error) {
	if req == nil || req.Id == nil || req.Id.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for DeleteExpectedMachine")
	}
	if _, ok := f.em[req.Id.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedMachine with ID %q not found", req.Id.Value)
	}
	delete(f.em, req.Id.Value)
	return &emptypb.Empty{}, nil
}

// CreateExpectedMachines implements interface NICoServer
func (f *NICoServerImpl) CreateExpectedMachines(ctx context.Context, req *cwssaws.BatchExpectedMachineOperationRequest) (*cwssaws.BatchExpectedMachineOperationResponse, error) {
	if req == nil || req.GetExpectedMachines() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request for CreateExpectedMachines")
	}
	emList := req.GetExpectedMachines().GetExpectedMachines()
	out := &cwssaws.BatchExpectedMachineOperationResponse{
		Results: make([]*cwssaws.ExpectedMachineOperationResult, 0, len(emList)),
	}
	for _, em := range emList {
		if em == nil {
			msg := "nil expected machine entry"
			out.Results = append(out.Results, &cwssaws.ExpectedMachineOperationResult{
				Success:         false,
				ErrorMessage:    &msg,
				ExpectedMachine: nil,
			})
			continue
		}
		result := &cwssaws.ExpectedMachineOperationResult{
			Id:              em.Id,
			Success:         true,
			ExpectedMachine: em,
		}
		if em.GetId() == nil || em.GetId().GetValue() == "" {
			result.Success = false
			msg := "ID not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else if em.GetBmcMacAddress() == "" {
			result.Success = false
			msg := "MAC address not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else if em.GetChassisSerialNumber() == "" {
			result.Success = false
			msg := "Chassis Serial Number not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else {
			f.em[em.Id.Value] = em
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

// UpdateExpectedMachines implements interface NICoServer
func (f *NICoServerImpl) UpdateExpectedMachines(ctx context.Context, req *cwssaws.BatchExpectedMachineOperationRequest) (*cwssaws.BatchExpectedMachineOperationResponse, error) {
	if req == nil || req.GetExpectedMachines() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request for UpdateExpectedMachines")
	}
	emList := req.GetExpectedMachines().GetExpectedMachines()
	out := &cwssaws.BatchExpectedMachineOperationResponse{
		Results: make([]*cwssaws.ExpectedMachineOperationResult, 0, len(emList)),
	}
	for _, em := range emList {
		if em == nil {
			msg := "nil expected machine entry"
			out.Results = append(out.Results, &cwssaws.ExpectedMachineOperationResult{
				Success:         false,
				ErrorMessage:    &msg,
				ExpectedMachine: nil,
			})
			continue
		}
		result := &cwssaws.ExpectedMachineOperationResult{
			Id:              em.Id,
			Success:         true,
			ExpectedMachine: em,
		}
		if em.GetId() == nil || em.GetId().GetValue() == "" {
			result.Success = false
			msg := "ID not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else if em.GetBmcMacAddress() == "" {
			result.Success = false
			msg := "MAC address not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else if em.GetChassisSerialNumber() == "" {
			result.Success = false
			msg := "Chassis Serial Number not provided"
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else if _, ok := f.em[em.Id.Value]; !ok {
			result.Success = false
			msg := fmt.Sprintf("ExpectedMachine with ID %q not found", em.Id.Value)
			result.ErrorMessage = &msg
			result.ExpectedMachine = nil
		} else {
			f.em[em.Id.Value] = em
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

// AddExpectedPowerShelf implements interface NICoServer
func (f *NICoServerImpl) AddExpectedPowerShelf(ctx context.Context, req *cwssaws.ExpectedPowerShelf) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedPowerShelfId == nil || req.ExpectedPowerShelfId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for AddExpectedPowerShelf")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for AddExpectedPowerShelf")
	}
	if req.ShelfSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Shelf Serial Number not provided for AddExpectedPowerShelf")
	}
	f.eps[req.ExpectedPowerShelfId.Value] = req
	return &emptypb.Empty{}, nil
}

// UpdateExpectedPowerShelf implements interface NICoServer
func (f *NICoServerImpl) UpdateExpectedPowerShelf(ctx context.Context, req *cwssaws.ExpectedPowerShelf) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedPowerShelfId == nil || req.ExpectedPowerShelfId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for UpdateExpectedPowerShelf")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for UpdateExpectedPowerShelf")
	}
	if req.ShelfSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Shelf Serial Number not provided for UpdateExpectedPowerShelf")
	}
	if _, ok := f.eps[req.ExpectedPowerShelfId.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedPowerShelf with ID %q not found", req.ExpectedPowerShelfId.Value)
	}
	f.eps[req.ExpectedPowerShelfId.Value] = req
	return &emptypb.Empty{}, nil
}

// DeleteExpectedPowerShelf implements interface NICoServer
func (f *NICoServerImpl) DeleteExpectedPowerShelf(ctx context.Context, req *cwssaws.ExpectedPowerShelfRequest) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedPowerShelfId == nil || req.ExpectedPowerShelfId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for DeleteExpectedPowerShelf")
	}
	if _, ok := f.eps[req.ExpectedPowerShelfId.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedPowerShelf with ID %q not found", req.ExpectedPowerShelfId.Value)
	}
	delete(f.eps, req.ExpectedPowerShelfId.Value)
	return &emptypb.Empty{}, nil
}

// GetExpectedPowerShelf implements interface NICoServer
func (f *NICoServerImpl) GetExpectedPowerShelf(ctx context.Context, req *cwssaws.ExpectedPowerShelfRequest) (*cwssaws.ExpectedPowerShelf, error) {
	if req == nil || req.ExpectedPowerShelfId == nil || req.ExpectedPowerShelfId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for GetExpectedPowerShelf")
	}
	eps, ok := f.eps[req.ExpectedPowerShelfId.Value]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedPowerShelf with ID %q not found", req.ExpectedPowerShelfId.Value)
	}
	return eps, nil
}

// GetAllExpectedPowerShelves implements interface NICoServer
func (f *NICoServerImpl) GetAllExpectedPowerShelves(ctx context.Context, req *emptypb.Empty) (*cwssaws.ExpectedPowerShelfList, error) {
	res := make([]*cwssaws.ExpectedPowerShelf, 0, len(f.eps))
	for _, eps := range f.eps {
		res = append(res, eps)
	}
	return &cwssaws.ExpectedPowerShelfList{ExpectedPowerShelves: res}, nil
}

// AddExpectedSwitch implements interface NICoServer
func (f *NICoServerImpl) AddExpectedSwitch(ctx context.Context, req *cwssaws.ExpectedSwitch) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedSwitchId == nil || req.ExpectedSwitchId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for AddExpectedSwitch")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for AddExpectedSwitch")
	}
	if req.SwitchSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Switch Serial Number not provided for AddExpectedSwitch")
	}
	f.es[req.ExpectedSwitchId.Value] = req
	return &emptypb.Empty{}, nil
}

// UpdateExpectedSwitch implements interface NICoServer
func (f *NICoServerImpl) UpdateExpectedSwitch(ctx context.Context, req *cwssaws.ExpectedSwitch) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedSwitchId == nil || req.ExpectedSwitchId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for UpdateExpectedSwitch")
	}
	if req.BmcMacAddress == "" {
		return nil, status.Errorf(codes.InvalidArgument, "MAC address not provided for UpdateExpectedSwitch")
	}
	if req.SwitchSerialNumber == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Switch Serial Number not provided for UpdateExpectedSwitch")
	}
	if _, ok := f.es[req.ExpectedSwitchId.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedSwitch with ID %q not found", req.ExpectedSwitchId.Value)
	}
	f.es[req.ExpectedSwitchId.Value] = req
	return &emptypb.Empty{}, nil
}

// DeleteExpectedSwitch implements interface NICoServer
func (f *NICoServerImpl) DeleteExpectedSwitch(ctx context.Context, req *cwssaws.ExpectedSwitchRequest) (*emptypb.Empty, error) {
	if req == nil || req.ExpectedSwitchId == nil || req.ExpectedSwitchId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for DeleteExpectedSwitch")
	}
	if _, ok := f.es[req.ExpectedSwitchId.Value]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedSwitch with ID %q not found", req.ExpectedSwitchId.Value)
	}
	delete(f.es, req.ExpectedSwitchId.Value)
	return &emptypb.Empty{}, nil
}

// GetExpectedSwitch implements interface NICoServer
func (f *NICoServerImpl) GetExpectedSwitch(ctx context.Context, req *cwssaws.ExpectedSwitchRequest) (*cwssaws.ExpectedSwitch, error) {
	if req == nil || req.ExpectedSwitchId == nil || req.ExpectedSwitchId.Value == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for GetExpectedSwitch")
	}
	es, ok := f.es[req.ExpectedSwitchId.Value]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedSwitch with ID %q not found", req.ExpectedSwitchId.Value)
	}
	return es, nil
}

// GetAllExpectedSwitches implements interface NICoServer
func (f *NICoServerImpl) GetAllExpectedSwitches(ctx context.Context, req *emptypb.Empty) (*cwssaws.ExpectedSwitchList, error) {
	res := make([]*cwssaws.ExpectedSwitch, 0, len(f.es))
	for _, es := range f.es {
		res = append(res, es)
	}
	return &cwssaws.ExpectedSwitchList{ExpectedSwitches: res}, nil
}

// AddExpectedRack implements interface NICoServer
func (f *NICoServerImpl) AddExpectedRack(ctx context.Context, req *cwssaws.ExpectedRack) (*emptypb.Empty, error) {
	if req == nil || req.RackId == nil || req.RackId.Id == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for AddExpectedRack")
	}
	if req.RackType == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Rack Profile ID not provided for AddExpectedRack")
	}
	f.er[req.RackId.Id] = req
	return &emptypb.Empty{}, nil
}

// UpdateExpectedRack implements interface NICoServer
func (f *NICoServerImpl) UpdateExpectedRack(ctx context.Context, req *cwssaws.ExpectedRack) (*emptypb.Empty, error) {
	if req == nil || req.RackId == nil || req.RackId.Id == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for UpdateExpectedRack")
	}
	if req.RackType == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Rack Profile ID not provided for UpdateExpectedRack")
	}
	if _, ok := f.er[req.RackId.Id]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedRack with ID %q not found", req.RackId.Id)
	}
	f.er[req.RackId.Id] = req
	return &emptypb.Empty{}, nil
}

// DeleteExpectedRack implements interface NICoServer
func (f *NICoServerImpl) DeleteExpectedRack(ctx context.Context, req *cwssaws.ExpectedRackRequest) (*emptypb.Empty, error) {
	if req == nil || req.RackId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for DeleteExpectedRack")
	}
	if _, ok := f.er[req.RackId]; !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedRack with ID %q not found", req.RackId)
	}
	delete(f.er, req.RackId)
	return &emptypb.Empty{}, nil
}

// GetExpectedRack implements interface NICoServer
func (f *NICoServerImpl) GetExpectedRack(ctx context.Context, req *cwssaws.ExpectedRackRequest) (*cwssaws.ExpectedRack, error) {
	if req == nil || req.RackId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ID not provided for GetExpectedRack")
	}
	er, ok := f.er[req.RackId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "ExpectedRack with ID %q not found", req.RackId)
	}
	return er, nil
}

// GetAllExpectedRacks implements interface NICoServer
func (f *NICoServerImpl) GetAllExpectedRacks(ctx context.Context, req *emptypb.Empty) (*cwssaws.ExpectedRackList, error) {
	res := make([]*cwssaws.ExpectedRack, 0, len(f.er))
	for _, er := range f.er {
		res = append(res, er)
	}
	return &cwssaws.ExpectedRackList{ExpectedRacks: res}, nil
}

// ReplaceAllExpectedRacks implements interface NICoServer
func (f *NICoServerImpl) ReplaceAllExpectedRacks(ctx context.Context, req *cwssaws.ExpectedRackList) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	for _, er := range req.ExpectedRacks {
		if er == nil || er.RackId == nil || er.RackId.Id == "" {
			return nil, status.Errorf(codes.InvalidArgument, "ID not provided for ReplaceAllExpectedRacks")
		}
		if er.RackType == "" {
			return nil, status.Errorf(codes.InvalidArgument, "Rack Profile ID not provided for ReplaceAllExpectedRacks")
		}
	}
	f.er = make(map[string]*cwssaws.ExpectedRack)
	for _, er := range req.ExpectedRacks {
		f.er[er.RackId.Id] = er
	}
	return &emptypb.Empty{}, nil
}

// DeleteAllExpectedRacks implements interface NICoServer
func (f *NICoServerImpl) DeleteAllExpectedRacks(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	f.er = make(map[string]*cwssaws.ExpectedRack)
	return &emptypb.Empty{}, nil
}

// LoadTestMachines loads test machines into the server
func (f *NICoServerImpl) LoadTestMachines() {
	nid := uuid.NewString()

	var memSize uint32 = 16384

	f.m[nid] = &cwssaws.Machine{
		Id:    &cwssaws.MachineId{Id: nid},
		State: "Ready",
		Interfaces: []*cwssaws.MachineInterface{
			{
				Id:                   &cwssaws.MachineInterfaceId{Value: uuid.NewString()},
				AttachedDpuMachineId: &cwssaws.MachineId{Id: uuid.NewString()},
				MachineId:            &cwssaws.MachineId{Id: nid},
				SegmentId:            &cwssaws.NetworkSegmentId{Value: uuid.NewString()},
				Hostname:             "nico.nvidia.com",
				PrimaryInterface:     true,
				MacAddress:           generateMacAddress(),
				Address:              []string{generateIPAddress()},
			},
		},
		DiscoveryInfo: &cwssaws.DiscoveryInfo{
			Cpus: []*cwssaws.Cpu{
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "1571.080",
					Number:    0,
					Core:      0,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "1571.080",
					Number:    1,
					Core:      0,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3371.751",
					Number:    2,
					Core:      0,
					Socket:    1,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3017.142",
					Number:    3,
					Core:      0,
					Socket:    1,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3507.275",
					Number:    4,
					Core:      1,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3255.853",
					Number:    5,
					Core:      1,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3530.777",
					Number:    6,
					Core:      1,
					Socket:    1,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3250.777",
					Number:    7,
					Core:      1,
					Socket:    1,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3250.777",
					Number:    8,
					Core:      2,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3250.777",
					Number:    9,
					Core:      2,
					Socket:    0,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3250.777",
					Number:    10,
					Core:      2,
					Socket:    1,
				},
				{
					Vendor:    "GenuineIntel",
					Model:     "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
					Frequency: "3250.777",
					Number:    11,
					Core:      2,
					Socket:    1,
				},
			},
			NetworkInterfaces: []*cwssaws.NetworkInterface{
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x14e4",
						Device:      "0x165f",
						Path:        "/devices/pci0000:00/0000:00:1c.5/0000:04:00.0/net/eno8303",
						Description: getStrPtr("NetXtreme BCM5720 2-port Gigabit Ethernet PCIe (PowerEdge Rx5xx LOM Board)"),
					},
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x14e4",
						Device:      "0x165f",
						Path:        "/devices/pci0000:00/0000:00:1c.5/0000:04:00.1/net/eno8403",
						Description: getStrPtr("NetXtreme BCM5720 2-port Gigabit Ethernet PCIe (PowerEdge Rx5xx LOM Board)"),
					},
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x14e4",
						Device:      "0x16d7",
						Path:        "/devices/pci0000:30/0000:30:04.0/0000:31:00.0/net/eno12399np0",
						Description: getStrPtr("BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller"),
					},
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x14e4",
						Device:      "0x16d7",
						Path:        "/devices/pci0000:30/0000:30:04.0/0000:31:00.1/net/eno12409np1",
						Description: getStrPtr("BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller"),
					},
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x15b3",
						Device:      "0xa2d6",
						Path:        "/devices/pci0000:b0/0000:b0:02.0/0000:b1:00.0/net/enp177s0f0np0",
						NumaNode:    1,
						Description: getStrPtr("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"),
					},
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "0x15b3",
						Device:      "0xa2d6",
						Path:        "/devices/pci0000:b0/0000:b0:02.0/0000:b1:00.1/net/enp177s0f1np1",
						NumaNode:    1,
						Description: getStrPtr("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"),
					},
				},
			},
			BlockDevices: []*cwssaws.BlockDevice{
				{
					Model:    "NO_MODEL",
					Revision: "NO_REVISION",
				},
				{
					Model:    "LOGICAL_VOLUME",
					Revision: "3.53",
					Serial:   "600508b1001cb4d1a278bf3ee7a72228",
				},
				{
					Model:    "Dell Ent NVMe CM6 RI 1.92TB",
					Revision: "2.1.3",
				},
				{
					Model:    "SSDPF2KE016T9L",
					Revision: "2CV1L028",
				},
				{
					Model:    "DELLBOSS_VD",
					Revision: "MV.R00-0",
				},
			},
			DmiData: &cwssaws.DmiData{
				BoardName:     "7Z23CTOLWW",
				BoardVersion:  "06",
				BiosVersion:   "U8E122J-1.51",
				ProductSerial: "J1050ACR",
				BoardSerial:   ".C1KS2CS001G.",
				ChassisSerial: "J1050ACR",
				BiosDate:      "03/30/2023",
				ProductName:   "ThinkSystem SR670 V2",
				SysVendor:     "Lenovo",
			},
			NvmeDevices: []*cwssaws.NvmeDevice{
				{
					Model:       "Dell Ent NVMe CM6 RI 1.92TB",
					FirmwareRev: "2.1.3",
				},
				{
					Model:       "Dell Ent NVMe CM6 RI 1.92TB",
					FirmwareRev: "2.1.3",
				},
				{
					Model:       "Dell Ent NVMe CM6 RI 1.92TB",
					FirmwareRev: "2.1.3",
				},
			},
			Gpus: []*cwssaws.Gpu{
				{
					Name:           "NVIDIA H100 PCIe",
					Serial:         "1654422005434",
					DriverVersion:  "530.30.02",
					VbiosVersion:   "96.00.30.00.01",
					InforomVersion: "1010.0200.00.02",
					TotalMemory:    "81559 MiB",
					Frequency:      "1755 MHz",
					PciBusId:       "00000000:17:00.0",
				},
			},
			MemoryDevices: []*cwssaws.MemoryDevice{
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  &memSize,
					MemType: getStrPtr("DDR4"),
				},
				{
					SizeMb:  nil,
					MemType: getStrPtr("UNKNOWN"),
				},
			},
			InfinibandInterfaces: []*cwssaws.InfinibandInterface{
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "Mellanox Technologies",
						Device:      "MT28908 Family [ConnectX-6]",
						Path:        "/devices/pci0000:c9/0000:c9:02.0/0000:ca:00.0/infiniband/rocep202s0f0",
						NumaNode:    1,
						Description: getStrPtr("MT28908 Family [ConnectX-6]"),
						Slot:        getStrPtr("0000:ca:00.0"),
					},
					Guid: "1070fd0300bd43ac",
				},
				{
					PciProperties: &cwssaws.PciDeviceProperties{
						Vendor:      "Mellanox Technologies",
						Device:      "MT28908 Family [ConnectX-6]",
						Path:        "/devices/pci0000:c9/0000:c9:02.0/0000:ca:00.1/infiniband/rocep202s0f1",
						NumaNode:    1,
						Description: getStrPtr("MT28908 Family [ConnectX-6]"),
						Slot:        getStrPtr("0000:ca:00.1"),
					},
					Guid: "1070fd0300bd43ad",
				},
			},
		},
	}
}

// ~~~~~ Machine Identity mock methods ~~~~~ //

const (
	jwtESAlg          = "ES256"
	p256CoordinateLen = 32
)

// generateES256KeyMaterial returns a fresh P-256 keypair with derived kid.
func generateES256KeyMaterial() (*identityKeyMaterial, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal SPKI: %w", err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	sum := sha256.Sum256([]byte(publicPEM))
	return &identityKeyMaterial{
		privateKey: priv,
		publicPEM:  publicPEM,
		kid:        hex.EncodeToString(sum[:]),
	}, nil
}

// jwksDocumentForKey returns a one-key JWKS JSON document.
func jwksDocumentForKey(km *identityKeyMaterial, use string) (string, error) {
	return jwksDocumentForKeys([]*identityKeyMaterial{km}, use)
}

// jwksDocumentForKeys returns a JWKS JSON document for the supplied keys
// (two during a rotation overlap window; one in steady state).
func jwksDocumentForKeys(kms []*identityKeyMaterial, use string) (string, error) {
	jwks := make([]map[string]string, 0, len(kms))
	for _, km := range kms {
		if km == nil || km.privateKey == nil {
			return "", fmt.Errorf("nil key material")
		}
		pub := km.privateKey.PublicKey
		xb := pub.X.FillBytes(make([]byte, p256CoordinateLen))
		yb := pub.Y.FillBytes(make([]byte, p256CoordinateLen))
		jwks = append(jwks, map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"alg": jwtESAlg,
			"use": use,
			"kid": km.kid,
			"x":   base64.RawURLEncoding.EncodeToString(xb),
			"y":   base64.RawURLEncoding.EncodeToString(yb),
		})
	}
	out, err := json.Marshal(map[string]any{"keys": jwks})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// signES256JWT returns a compact-serialized ES256 JWS.
func signES256JWT(priv *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]string{"alg": jwtESAlg, "kid": kid, "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}
	sig := make([]byte, 2*p256CoordinateLen)
	r.FillBytes(sig[:p256CoordinateLen])
	s.FillBytes(sig[p256CoordinateLen:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// clientSecretDisplayHash returns the truncated SHA-256 display form.
func clientSecretDisplayHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	full := hex.EncodeToString(sum[:])
	if len(full) >= 8 {
		return "sha256:" + full[:8] + ".."
	}
	return "sha256:" + full
}

// resolveSubjectPrefix mirrors carbide-core's `resolve_subject_prefix`:
// derives `spiffe://<trust-domain-from-issuer>` from the issuer URL host.
func resolveSubjectPrefix(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ""
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	return "spiffe://" + host
}

// normalizeAllowedAudiences defaults to [defaultAud] when empty; otherwise defaultAud must appear in allowed.
func normalizeAllowedAudiences(defaultAud string, allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		return []string{defaultAud}, nil
	}
	for _, a := range allowed {
		if a == defaultAud {
			out := make([]string, len(allowed))
			copy(out, allowed)
			return out, nil
		}
	}
	return nil, fmt.Errorf("default_audience %q must appear in allowed_audiences", defaultAud)
}

// SetTenantIdentityConfiguration implements interface NICoServer
func (f *NICoServerImpl) SetTenantIdentityConfiguration(ctx context.Context, req *cwssaws.SetTenantIdentityConfigRequest) (*cwssaws.TenantIdentityConfigResponse, error) {
	if req == nil || req.GetOrganizationId() == "" || req.GetConfig() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	in := req.GetConfig()
	if strings.TrimSpace(in.GetIssuer()) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "issuer is required")
	}
	if strings.TrimSpace(in.GetDefaultAudience()) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "default_audience is required")
	}
	if in.GetTokenTtlSec() == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "token_ttl_sec must be greater than zero")
	}
	allowed, err := normalizeAllowedAudiences(in.GetDefaultAudience(), in.GetAllowedAudiences())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	switch {
	case in.GetRotateKey() && in.SigningKeyOverlapSec == nil:
		return nil, status.Errorf(codes.InvalidArgument, "signing_key_overlap_sec is required when rotate_key is true")
	case !in.GetRotateKey() && in.SigningKeyOverlapSec != nil:
		return nil, status.Errorf(codes.InvalidArgument, "signing_key_overlap_sec must be omitted when rotate_key is false")
	case in.GetRotateKey() && in.SigningKeyOverlapSec != nil && *in.SigningKeyOverlapSec < in.GetTokenTtlSec():
		return nil, status.Errorf(codes.InvalidArgument, "signing_key_overlap_sec must be >= token_ttl_sec")
	}

	orgID := req.GetOrganizationId()
	f.gcExpiredNonActiveSigningKey(orgID)
	now := timestamppb.Now()
	st, isUpdate := f.identityState[orgID]
	if !isUpdate {
		st = &identityOrgState{}
		f.identityState[orgID] = st
	}

	switch {
	case !isUpdate:
		newKey, err := generateES256KeyMaterial()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to generate signing key: %v", err)
		}
		st.slot1 = newKey
		st.slot2 = nil
		st.currentSlot = 1
		st.nonActiveSlotExpires = nil
	case in.GetRotateKey():
		st.clearInactiveSlot()
		newKey, err := generateES256KeyMaterial()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to generate signing key: %v", err)
		}
		st.setSlot(st.inactiveSlot(), newKey)
		st.currentSlot = st.inactiveSlot()
		expire := now.AsTime().Add(time.Duration(*in.SigningKeyOverlapSec) * time.Second)
		st.nonActiveSlotExpires = &expire
	}

	resolvedSubjectPrefix := in.SubjectPrefix
	if resolvedSubjectPrefix == nil || strings.TrimSpace(*resolvedSubjectPrefix) == "" {
		if derived := resolveSubjectPrefix(in.GetIssuer()); derived != "" {
			resolvedSubjectPrefix = &derived
		}
	}

	resp := &cwssaws.TenantIdentityConfigResponse{
		OrganizationId: orgID,
		Config: &cwssaws.TenantIdentityConfig{
			Enabled:          in.GetEnabled(),
			Issuer:           in.GetIssuer(),
			DefaultAudience:  in.GetDefaultAudience(),
			AllowedAudiences: allowed,
			TokenTtlSec:      in.GetTokenTtlSec(),
			SubjectPrefix:    resolvedSubjectPrefix,
			RotateKey:        st.nonActiveSlotExpires != nil,
		},
		UpdatedAt: now,
	}
	if isUpdate {
		resp.CreatedAt = st.cfg.GetCreatedAt()
	} else {
		resp.CreatedAt = now
	}
	resp.SigningKeys = tenantIdentitySigningKeysResponse(st)
	st.cfg = resp
	return resp, nil
}

// GetTenantIdentityConfiguration implements interface NICoServer
func (f *NICoServerImpl) GetTenantIdentityConfiguration(ctx context.Context, req *cwssaws.GetTenantIdentityConfigRequest) (*cwssaws.TenantIdentityConfigResponse, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := req.GetOrganizationId()
	f.gcExpiredNonActiveSigningKey(orgID)
	st, ok := f.identityState[orgID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Identity configuration not found for org %q", orgID)
	}
	resp := cloneTenantIdentityConfigResponse(st.cfg)
	resp.SigningKeys = tenantIdentitySigningKeysResponse(st)
	if cfg := resp.GetConfig(); cfg != nil {
		cfg.RotateKey = st.nonActiveSlotExpires != nil
	}
	return resp, nil
}

func cloneTenantIdentityConfigResponse(in *cwssaws.TenantIdentityConfigResponse) *cwssaws.TenantIdentityConfigResponse {
	if in == nil {
		return nil
	}
	out := &cwssaws.TenantIdentityConfigResponse{
		OrganizationId: in.GetOrganizationId(),
		CreatedAt:      in.GetCreatedAt(),
		UpdatedAt:      in.GetUpdatedAt(),
	}
	if cfg := in.GetConfig(); cfg != nil {
		out.Config = &cwssaws.TenantIdentityConfig{
			Enabled:              cfg.GetEnabled(),
			Issuer:               cfg.GetIssuer(),
			DefaultAudience:      cfg.GetDefaultAudience(),
			AllowedAudiences:     cfg.GetAllowedAudiences(),
			TokenTtlSec:          cfg.GetTokenTtlSec(),
			SubjectPrefix:        cfg.SubjectPrefix,
			RotateKey:            cfg.GetRotateKey(),
			SigningKeyOverlapSec: cfg.SigningKeyOverlapSec,
		}
	}
	return out
}

// DeleteTenantIdentityConfiguration implements interface NICoServer
func (f *NICoServerImpl) DeleteTenantIdentityConfiguration(ctx context.Context, req *cwssaws.GetTenantIdentityConfigRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := req.GetOrganizationId()
	if _, ok := f.identityState[orgID]; !ok {
		return nil, status.Errorf(codes.NotFound, "Identity configuration not found for org %q", orgID)
	}
	delete(f.identityState, orgID)
	delete(f.tokenDelegations, orgID)
	return &emptypb.Empty{}, nil
}

// SetTokenDelegation implements interface NICoServer
func (f *NICoServerImpl) SetTokenDelegation(ctx context.Context, req *cwssaws.TokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	if req == nil || req.GetOrganizationId() == "" || req.GetConfig() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := req.GetOrganizationId()
	in := req.GetConfig()
	if strings.TrimSpace(in.GetTokenEndpoint()) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token_endpoint is required")
	}
	if strings.TrimSpace(in.GetSubjectTokenAudience()) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "subject_token_audience is required")
	}

	if _, ok := f.identityState[orgID]; !ok {
		return nil, status.Errorf(codes.NotFound, "Identity configuration must exist before token delegation is set for org %q", orgID)
	}

	now := timestamppb.Now()
	existing, isUpdate := f.tokenDelegations[orgID]

	resp := &cwssaws.TokenDelegationResponse{
		OrganizationId:       orgID,
		TokenEndpoint:        in.GetTokenEndpoint(),
		SubjectTokenAudience: in.GetSubjectTokenAudience(),
		UpdatedAt:            now,
	}
	if basic := in.GetClientSecretBasic(); basic != nil {
		if strings.TrimSpace(basic.GetClientId()) == "" {
			return nil, status.Errorf(codes.InvalidArgument, "client_id is required for client_secret_basic")
		}
		if strings.TrimSpace(basic.GetClientSecret()) == "" {
			return nil, status.Errorf(codes.InvalidArgument, "client_secret is required for client_secret_basic")
		}
		resp.AuthMethodConfig = &cwssaws.TokenDelegationResponse_ClientSecretBasic{
			ClientSecretBasic: &cwssaws.ClientSecretBasicResponse{
				ClientId:         basic.GetClientId(),
				ClientSecretHash: clientSecretDisplayHash(basic.GetClientSecret()),
			},
		}
	}
	if isUpdate {
		resp.CreatedAt = existing.GetCreatedAt()
	} else {
		resp.CreatedAt = now
	}

	f.tokenDelegations[orgID] = resp
	return resp, nil
}

// GetTokenDelegation implements interface NICoServer
func (f *NICoServerImpl) GetTokenDelegation(ctx context.Context, req *cwssaws.GetTokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	td, ok := f.tokenDelegations[req.GetOrganizationId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Token delegation not found for org %q", req.GetOrganizationId())
	}
	return td, nil
}

// DeleteTokenDelegation implements interface NICoServer. Idempotent: a
// missing entry returns success (matches carbide-core's no-op delete).
func (f *NICoServerImpl) DeleteTokenDelegation(ctx context.Context, req *cwssaws.GetTokenDelegationRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	delete(f.tokenDelegations, req.GetOrganizationId())
	return &emptypb.Empty{}, nil
}

// GetJWKS implements interface NICoServer
func (f *NICoServerImpl) GetJWKS(ctx context.Context, req *cwssaws.JwksRequest) (*cwssaws.Jwks, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := req.GetOrganizationId()
	f.gcExpiredNonActiveSigningKey(orgID)
	st, hasCfg := f.identityState[orgID]
	if !hasCfg {
		return nil, status.Errorf(codes.NotFound, "Identity configuration not found for org %q", orgID)
	}
	use := "sig"
	if req.GetKind() == cwssaws.JwksKind_Spiffe {
		use = "jwt-svid"
	}
	keys := []*identityKeyMaterial{}
	if active := st.activeKey(); active != nil {
		keys = append(keys, active)
	}
	if inactive := st.inactiveKey(); inactive != nil {
		keys = append(keys, inactive)
	}
	if len(keys) == 0 {
		return nil, status.Errorf(codes.Internal, "Signing key missing for org %q (mock state inconsistent)", orgID)
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].kid < keys[j].kid })
	doc, err := jwksDocumentForKeys(keys, use)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize JWKS: %v", err)
	}
	return &cwssaws.Jwks{Jwks: doc}, nil
}

// GetOpenIDConfiguration implements interface NICoServer
func (f *NICoServerImpl) GetOpenIDConfiguration(ctx context.Context, req *cwssaws.OpenIdConfigRequest) (*cwssaws.OpenIdConfiguration, error) {
	if req == nil || req.GetOrganizationId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := req.GetOrganizationId()
	f.gcExpiredNonActiveSigningKey(orgID)
	st, ok := f.identityState[orgID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Identity configuration not found for org %q", orgID)
	}
	iss := st.cfg.GetConfig().GetIssuer()
	if strings.TrimSpace(iss) == "" {
		return nil, status.Errorf(codes.NotFound, "Issuer not configured for org %q", orgID)
	}
	if st.activeKey() == nil {
		return nil, status.Errorf(codes.NotFound, "No active signing key for org %q", orgID)
	}
	base := strings.TrimRight(iss, "/")
	return &cwssaws.OpenIdConfiguration{
		Issuer:                           iss,
		JwksUri:                          base + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"token"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{},
		SpiffeJwksUri:                    base + "/.well-known/spiffe/jwks.json",
	}, nil
}

// resolveSigningOrg returns the seeded org when exactly one identity is configured,
// otherwise the empty string.
func (f *NICoServerImpl) resolveSigningOrg(_ context.Context) string {
	if len(f.identityState) == 1 {
		for k := range f.identityState {
			return k
		}
	}
	return ""
}

// SignMachineIdentity implements interface NICoServer
func (f *NICoServerImpl) SignMachineIdentity(ctx context.Context, req *cwssaws.MachineIdentityRequest) (*cwssaws.MachineIdentityResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request argument")
	}
	orgID := f.resolveSigningOrg(ctx)
	if orgID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "Cannot resolve signing org; seed exactly one identity in the mock")
	}
	st, hasCfg := f.identityState[orgID]
	if !hasCfg {
		return nil, status.Errorf(codes.NotFound, "Identity configuration not found for org %q", orgID)
	}
	km := st.activeKey()
	if km == nil {
		return nil, status.Errorf(codes.Internal, "Signing key missing for org %q (mock state inconsistent)", orgID)
	}
	cfg := st.cfg

	audiences := req.GetAudience()
	if len(audiences) == 0 {
		audiences = []string{cfg.GetConfig().GetDefaultAudience()}
	} else {
		allowed := make(map[string]struct{}, len(cfg.GetConfig().GetAllowedAudiences()))
		for _, a := range cfg.GetConfig().GetAllowedAudiences() {
			allowed[a] = struct{}{}
		}
		for _, a := range audiences {
			if _, ok := allowed[a]; !ok {
				return nil, status.Errorf(codes.InvalidArgument, "audience %q is not in allowed_audiences", a)
			}
		}
	}

	ttl := int64(cfg.GetConfig().GetTokenTtlSec())
	if ttl <= 0 {
		ttl = 600
	}
	now := time.Now().Unix()

	subjectPrefix := cfg.GetConfig().GetSubjectPrefix()
	if subjectPrefix == "" {
		subjectPrefix = strings.TrimRight(cfg.GetConfig().GetIssuer(), "/") + "/machine"
	}
	sub := strings.TrimRight(subjectPrefix, "/") + "/" + uuid.NewString()

	var aud any = audiences[0]
	if len(audiences) > 1 {
		aud = audiences
	}
	claims := map[string]any{
		"iss": cfg.GetConfig().GetIssuer(),
		"sub": sub,
		"aud": aud,
		"iat": now,
		"nbf": now,
		"exp": now + ttl,
		"jti": uuid.NewString(),
	}

	token, err := signES256JWT(km.privateKey, km.kid, claims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign token: %v", err)
	}
	return &cwssaws.MachineIdentityResponse{
		AccessToken:     token,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenType:       "Bearer",
		ExpiresInSec:    uint32(ttl),
	}, nil
}

// LoadTestIdentity seeds one example identity configuration.
func (f *NICoServerImpl) LoadTestIdentity() {
	const seedOrg = "test-org"
	if f.identityState == nil {
		f.identityState = make(map[string]*identityOrgState)
	}
	km, err := generateES256KeyMaterial()
	if err != nil {
		logger.Fatal().Err(err).Msg("LoadTestIdentity: failed to generate ES256 keypair")
		return
	}
	now := timestamppb.Now()
	st := &identityOrgState{
		slot1:       km,
		currentSlot: 1,
	}
	st.cfg = &cwssaws.TenantIdentityConfigResponse{
		OrganizationId: seedOrg,
		Config: &cwssaws.TenantIdentityConfig{
			Enabled:          true,
			Issuer:           "https://carbide-rest.mock/v2/org/test-org/nico/site/mock-site",
			DefaultAudience:  "openbao",
			AllowedAudiences: []string{"openbao", "vault"},
			TokenTtlSec:      600,
		},
		CreatedAt:   now,
		UpdatedAt:   now,
		SigningKeys: tenantIdentitySigningKeysResponse(st),
	}
	f.identityState[seedOrg] = st
}

// NICoTest tests the grpc server
func NICoTest(secs int) {
	listener, err := net.Listen("tcp", DefaultPort)
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	reflection.Register(s)

	nicoServer := &NICoServerImpl{
		v:                make(map[string]*cwssaws.Vpc),
		ns:               make(map[string]*cwssaws.NetworkSegment),
		ins:              make(map[string]*cwssaws.Instance),
		m:                make(map[string]*cwssaws.Machine),
		tk:               make(map[string]*cwssaws.TenantKeyset),
		ibp:              make(map[string]*cwssaws.IBPartition),
		em:               make(map[string]*cwssaws.ExpectedMachine),
		eps:              make(map[string]*cwssaws.ExpectedPowerShelf),
		es:               make(map[string]*cwssaws.ExpectedSwitch),
		er:               make(map[string]*cwssaws.ExpectedRack),
		identityState:    make(map[string]*identityOrgState),
		tokenDelegations: make(map[string]*cwssaws.TokenDelegationResponse),
	}
	nicoServer.LoadTestMachines()
	nicoServer.LoadTestIdentity()

	cwssaws.RegisterForgeServer(s, nicoServer)

	if secs != 0 {
		timer := time.AfterFunc(time.Second*time.Duration(secs), func() {
			s.GracefulStop()
			logger.Info().Msgf("Timer started for: %v seconds", secs)
		})
		defer timer.Stop()
	}

	logger.Info().Msg("Started API server")

	err = s.Serve(listener)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to start API server")
	}

	logger.Info().Msg("Stopped API server")
}
