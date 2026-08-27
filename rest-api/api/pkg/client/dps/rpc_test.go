// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dps

import (
	"context"
	"net"
	"testing"
	"time"

	dpsv1 "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/dps/internal/dpssdk/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testDPSServer struct {
	dpsv1.UnimplementedResourceGroupManagementServiceServer
	dpsv1.UnimplementedTopologyManagementServiceServer

	policies         []string
	policyCalls      int
	policyErrors     []error
	validateCalls    int
	validateErrors   []error
	validateRequest  *dpsv1.ValidateAllocationRequest
	validationResult *dpsv1.ValidateAllocationResponse_AllocationValidationResult
	createRequest    *dpsv1.ResourceGroupCreateRequest
	addRequest       *dpsv1.ResourceGroupAddResourcesRequest
	updateRequest    *dpsv1.ResourceGroupUpdateResourcesRequest
	removeRequest    *dpsv1.ResourceGroupRemoveResourcesRequest
	activateRequest  *dpsv1.ActivateResourceGroupRequest
	deleteRequest    *dpsv1.ResourceGroupDeleteRequest
	activateGroup    string
	deleteGroup      string
	deleteError      error
	activateError    error
	responseStatus   *dpsv1.Status
}

func (s *testDPSServer) ListPolicies(_ *emptypb.Empty, stream dpsv1.TopologyManagementService_ListPoliciesServer) error {
	s.policyCalls++
	if s.policyCalls <= len(s.policyErrors) && s.policyErrors[s.policyCalls-1] != nil {
		return s.policyErrors[s.policyCalls-1]
	}
	for _, name := range s.policies {
		err := stream.Send(&dpsv1.PolicyObject{Name: name})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *testDPSServer) ValidateAllocation(request *dpsv1.ValidateAllocationRequest, stream dpsv1.TopologyManagementService_ValidateAllocationServer) error {
	s.validateCalls++
	s.validateRequest = request
	if s.validateCalls <= len(s.validateErrors) && s.validateErrors[s.validateCalls-1] != nil {
		return s.validateErrors[s.validateCalls-1]
	}
	if s.validationResult == nil {
		return nil
	}
	return stream.Send(&dpsv1.ValidateAllocationResponse{
		Response: &dpsv1.ValidateAllocationResponse_AllocationValidationResult_{
			AllocationValidationResult: s.validationResult,
		},
	})
}

func (s *testDPSServer) ResourceGroupCreate(_ context.Context, request *dpsv1.ResourceGroupCreateRequest) (*dpsv1.ResourceGroupCreateResponse, error) {
	s.createRequest = request
	return &dpsv1.ResourceGroupCreateResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) ResourceGroupDelete(_ context.Context, request *dpsv1.ResourceGroupDeleteRequest) (*dpsv1.ResourceGroupDeleteResponse, error) {
	s.deleteRequest = request
	s.deleteGroup = request.GetGroupName()
	if s.deleteError != nil {
		return nil, s.deleteError
	}
	return &dpsv1.ResourceGroupDeleteResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) ResourceGroupAddResources(_ context.Context, request *dpsv1.ResourceGroupAddResourcesRequest) (*dpsv1.ResourceGroupAddResourcesResponse, error) {
	s.addRequest = request
	return &dpsv1.ResourceGroupAddResourcesResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) ResourceGroupRemoveResources(_ context.Context, request *dpsv1.ResourceGroupRemoveResourcesRequest) (*dpsv1.ResourceGroupRemoveResourcesResponse, error) {
	s.removeRequest = request
	return &dpsv1.ResourceGroupRemoveResourcesResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) ActivateResourceGroup(_ context.Context, request *dpsv1.ActivateResourceGroupRequest) (*dpsv1.ActivateResourceGroupResponse, error) {
	s.activateRequest = request
	s.activateGroup = request.GetGroupName()
	if s.activateError != nil {
		return nil, s.activateError
	}
	return &dpsv1.ActivateResourceGroupResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) ResourceGroupUpdateResources(_ context.Context, request *dpsv1.ResourceGroupUpdateResourcesRequest) (*dpsv1.ResourceGroupUpdateResourcesResponse, error) {
	s.updateRequest = request
	return &dpsv1.ResourceGroupUpdateResourcesResponse{Status: s.okStatus()}, nil
}

func (s *testDPSServer) okStatus() *dpsv1.Status {
	if s.responseStatus != nil {
		return s.responseStatus
	}
	return &dpsv1.Status{Ok: true}
}

func newTestClient(t *testing.T, server *testDPSServer) *Client {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	dpsv1.RegisterTopologyManagementServiceServer(grpcServer, server)
	dpsv1.RegisterResourceGroupManagementServiceServer(grpcServer, server)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	connection, err := grpc.NewClient(
		"passthrough:///dps-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })

	client := newClient(connection, time.Second)
	client.retryWait = 0
	return client
}

func TestClient_ListPowerProfiles(t *testing.T) {
	tests := []struct {
		name          string
		server        *testDPSServer
		expected      []string
		expectedCalls int
	}{
		{
			name:          "normalizes policy names",
			server:        &testDPSServer{policies: []string{" balanced ", "performance", "", "balanced"}},
			expected:      []string{"balanced", "performance"},
			expectedCalls: 1,
		},
		{
			name:          "retries unavailable once",
			server:        &testDPSServer{policies: []string{"performance"}, policyErrors: []error{status.Error(codes.Unavailable, "retry")}},
			expected:      []string{"performance"},
			expectedCalls: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t, test.server)
			profiles, err := client.ListPowerProfiles(context.Background())
			require.NoError(t, err)
			assert.Equal(t, test.expected, profiles)
			assert.Equal(t, test.expectedCalls, test.server.policyCalls)
		})
	}
}

func TestClient_ResourceGroupLifecycleRequests(t *testing.T) {
	server := &testDPSServer{}
	client := newTestClient(t, server)
	ctx := context.Background()

	require.NoError(t, client.CreateResourceGroup(ctx, " group-a ", 42))
	require.NoError(t, client.AddMachines(ctx, "group-a", []string{" machine-a ", "machine-b"}, " performance "))
	require.NoError(t, client.UpdateMachineProfile(ctx, "group-a", "machine-a", ""))
	require.NoError(t, client.RemoveMachines(ctx, "group-a", []string{"machine-a", "machine-b"}))
	require.NoError(t, client.ActivateResourceGroup(ctx, "group-a"))
	require.NoError(t, client.DeleteResourceGroup(ctx, "group-a"))

	require.NotNil(t, server.createRequest)
	assert.Equal(t, "group-a", server.createRequest.GetGroupName())
	assert.EqualValues(t, 42, server.createRequest.GetExternalId())
	assert.True(t, server.createRequest.GetDpmEnable())
	assert.True(t, server.createRequest.GetPrsEnabled())
	assert.True(t, server.createRequest.GetSharedGpuEnable())

	require.NotNil(t, server.addRequest)
	assert.Equal(t, []string{"machine-a", "machine-b"}, server.addRequest.GetResourceNames())
	assert.True(t, server.addRequest.GetStrict())
	assert.False(t, server.addRequest.GetAllowReprovision())
	require.NotNil(t, server.addRequest.PolicyName)
	assert.Equal(t, "performance", server.addRequest.GetPolicyName())

	require.NotNil(t, server.updateRequest)
	assert.Nil(t, server.updateRequest.GetAsync())
	require.Len(t, server.updateRequest.GetUpdates(), 1)
	update := server.updateRequest.GetUpdates()[0]
	assert.Equal(t, "machine-a", update.GetResourceName())
	require.IsType(t, &dpsv1.ResourceGroupUpdateResourcesRequest_ResourcePolicy_PolicyName{}, update.GetPolicyUpdate())
	assert.Equal(t, "", update.GetPolicyName())

	require.NotNil(t, server.removeRequest)
	assert.Equal(t, []string{"machine-a", "machine-b"}, server.removeRequest.GetResourceNames())
	assert.Equal(t, "group-a", server.activateGroup)
	assert.True(t, server.activateRequest.GetStrict())
	assert.False(t, server.activateRequest.GetAllowReprovision())
	assert.Nil(t, server.activateRequest.GetAsync())
	assert.Equal(t, "group-a", server.deleteGroup)
	assert.True(t, server.deleteRequest.GetWppsDisableAsyncVerification())
}

func TestClient_ValidateAllocation(t *testing.T) {
	tests := []struct {
		name          string
		server        *testDPSServer
		expectedError error
		expectedCalls int
	}{
		{
			name: "accepts allocation",
			server: &testDPSServer{validationResult: &dpsv1.ValidateAllocationResponse_AllocationValidationResult{
				Status:                 &dpsv1.Status{Ok: true},
				AllocationWouldSucceed: true,
			}},
			expectedCalls: 1,
		},
		{
			name: "rejects denied allocation",
			server: &testDPSServer{validationResult: &dpsv1.ValidateAllocationResponse_AllocationValidationResult{
				Status: &dpsv1.Status{Ok: true},
			}},
			expectedError: errAllocationRejected,
			expectedCalls: 1,
		},
		{
			name: "retries unavailable once",
			server: &testDPSServer{
				validateErrors: []error{status.Error(codes.Unavailable, "retry")},
				validationResult: &dpsv1.ValidateAllocationResponse_AllocationValidationResult{
					Status:                 &dpsv1.Status{Ok: true},
					AllocationWouldSucceed: true,
				},
			},
			expectedCalls: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t, test.server)
			err := client.ValidateAllocation(context.Background(), []string{" machine-b ", "machine-a", "machine-a"}, " performance ")
			if test.expectedError == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.expectedError)
			}
			assert.Equal(t, test.expectedCalls, test.server.validateCalls)
			require.NotNil(t, test.server.validateRequest)
			assert.Equal(t, []string{"machine-a", "machine-b"}, test.server.validateRequest.GetDeviceNames())
			assert.Equal(t, "performance", test.server.validateRequest.GetPolicyName())
			assert.True(t, test.server.validateRequest.GetStrict())
		})
	}
}

func TestClient_IdempotentLifecycleResponses(t *testing.T) {
	tests := []struct {
		name   string
		server *testDPSServer
		call   func(context.Context, *Client) error
	}{
		{
			name:   "delete missing group",
			server: &testDPSServer{deleteError: status.Error(codes.NotFound, "missing")},
			call: func(ctx context.Context, client *Client) error {
				return client.DeleteResourceGroup(ctx, "group-a")
			},
		},
		{
			name:   "activate active group",
			server: &testDPSServer{activateError: status.Error(codes.FailedPrecondition, "already active")},
			call: func(ctx context.Context, client *Client) error {
				return client.ActivateResourceGroup(ctx, "group-a")
			},
		},
		{
			name:   "activate active response status",
			server: &testDPSServer{responseStatus: &dpsv1.Status{DiagMsg: "resource group already active"}},
			call: func(ctx context.Context, client *Client) error {
				return client.ActivateResourceGroup(ctx, "group-a")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t, test.server)
			require.NoError(t, test.call(context.Background(), client))
		})
	}
}

func TestClient_ResponseStatusFailure(t *testing.T) {
	client := newTestClient(t, &testDPSServer{
		responseStatus: &dpsv1.Status{DiagMsg: "topology is inactive"},
	})

	err := client.CreateResourceGroup(context.Background(), "group-a", 42)

	require.ErrorContains(t, err, "topology is inactive")
}

func TestClient_ResponseStatusMissingFailsClosed(t *testing.T) {
	err := responseStatus("ValidateAllocation", nil)
	require.ErrorContains(t, err, "missing operation status")
}

func TestClient_RejectsEmptyAssociationNames(t *testing.T) {
	client := newTestClient(t, &testDPSServer{})

	tests := []struct {
		name string
		call func() error
	}{
		{name: "resource group", call: func() error {
			return client.AddMachine(context.Background(), " ", "machine-a", "")
		}},
		{name: "machine ID", call: func() error {
			return client.AddMachine(context.Background(), "group-a", " ", "")
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.call(), "required")
		})
	}
}
