// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoapi

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type recordingForgeClient struct {
	corev1.ForgeClient

	runtimeConfig   *corev1.RuntimeConfig
	versionErr      error
	versionRequests []*corev1.VersionRequest
	machineIDs      []string
	machineBatches  [][]string
	switchBatches   [][]string
	shelfBatches    [][]string
	failCall        int
	omitID          string
}

func (c *recordingForgeClient) Version(
	_ context.Context,
	request *corev1.VersionRequest,
	_ ...grpc.CallOption,
) (*corev1.BuildInfo, error) {
	c.versionRequests = append(c.versionRequests, request)
	if c.versionErr != nil {
		return nil, c.versionErr
	}
	return &corev1.BuildInfo{BuildVersion: "test", RuntimeConfig: c.runtimeConfig}, nil
}

func (c *recordingForgeClient) FindMachineIds(
	_ context.Context,
	_ *corev1.MachineSearchConfig,
	_ ...grpc.CallOption,
) (*corev1.MachineIdList, error) {
	return &corev1.MachineIdList{MachineIds: stringsToMachineIds(c.machineIDs)}, nil
}

func (c *recordingForgeClient) FindMachinesByIds(
	_ context.Context,
	request *corev1.MachinesByIdsRequest,
	_ ...grpc.CallOption,
) (*corev1.MachineList, error) {
	batch := machineIDsToStrings(request.GetMachineIds())
	c.machineBatches = append(c.machineBatches, batch)
	if c.failCall == len(c.machineBatches) {
		return nil, errors.New("injected machine lookup failure")
	}

	machines := make([]*corev1.Machine, 0, len(batch))
	for _, id := range batch {
		if id != c.omitID {
			machines = append(machines, &corev1.Machine{Id: &corev1.MachineId{Id: id}})
		}
	}
	return &corev1.MachineList{Machines: machines}, nil
}

func (c *recordingForgeClient) FindSwitchesByIds(
	_ context.Context,
	request *corev1.SwitchesByIdsRequest,
	_ ...grpc.CallOption,
) (*corev1.SwitchList, error) {
	batch := switchIDsToStrings(request.GetSwitchIds())
	c.switchBatches = append(c.switchBatches, batch)
	if c.failCall == len(c.switchBatches) {
		return nil, errors.New("injected switch lookup failure")
	}

	switches := make([]*corev1.Switch, 0, len(batch))
	for _, id := range batch {
		if id != c.omitID {
			nvosIP := "ip-" + id
			switches = append(switches, &corev1.Switch{
				Id:              &corev1.SwitchId{Id: id},
				RackId:          &corev1.RackId{Id: "rack-" + id},
				ControllerState: "state-" + id,
				NvosInfo:        &corev1.SwitchNvosInfo{Ip: &nvosIP},
			})
		}
	}
	return &corev1.SwitchList{Switches: switches}, nil
}

func (c *recordingForgeClient) FindPowerShelvesByIds(
	_ context.Context,
	request *corev1.PowerShelvesByIdsRequest,
	_ ...grpc.CallOption,
) (*corev1.PowerShelfList, error) {
	batch := powerShelfIDsToStrings(request.GetPowerShelfIds())
	c.shelfBatches = append(c.shelfBatches, batch)
	if c.failCall == len(c.shelfBatches) {
		return nil, errors.New("injected power shelf lookup failure")
	}

	shelves := make([]*corev1.PowerShelf, 0, len(batch))
	for _, id := range batch {
		if id != c.omitID {
			shelves = append(shelves, &corev1.PowerShelf{
				Id:              &corev1.PowerShelfId{Id: id},
				RackId:          &corev1.RackId{Id: "rack-" + id},
				ControllerState: "state-" + id,
			})
		}
	}
	return &corev1.PowerShelfList{PowerShelves: shelves}, nil
}

func newRecordingGRPCClient(fake *recordingForgeClient) *grpcClient {
	return &grpcClient{gclient: newBatchingForgeClient(fake), grpcTimeout: time.Second}
}

func TestGrpcClient_ByIDLookupsHonorCoreBatchLimit(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e"}
	expectedBatches := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}

	tests := []struct {
		name       string
		invoke     func(context.Context, *grpcClient, []string) (int, error)
		batchCalls func(*recordingForgeClient) [][]string
	}{
		{
			name: "listed machines",
			invoke: func(ctx context.Context, client *grpcClient, _ []string) (int, error) {
				machines, err := client.GetMachines(ctx)
				return len(machines), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.machineBatches },
		},
		{
			name: "machines by IDs",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				machines, err := client.FindMachinesByIds(ctx, ids)
				return len(machines), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.machineBatches },
		},
		{
			name: "direct switch lookup",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				request := &corev1.SwitchesByIdsRequest{
					SwitchIds: make([]*corev1.SwitchId, 0, len(ids)),
				}
				for _, id := range ids {
					request.SwitchIds = append(request.SwitchIds, &corev1.SwitchId{Id: id})
				}
				response, err := client.gclient.FindSwitchesByIds(ctx, request)
				return len(response.GetSwitches()), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.switchBatches },
		},
		{
			name: "switch rack IDs",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				values, err := client.FindSwitchRackIDs(ctx, ids)
				return len(values), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.switchBatches },
		},
		{
			name: "switch controller states",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				values, err := client.FindSwitchControllerStates(ctx, ids)
				return len(values), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.switchBatches },
		},
		{
			name: "switch NVOS IPs",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				values, err := client.FindSwitchNvosIPs(ctx, ids)
				return len(values), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.switchBatches },
		},
		{
			name: "power shelf rack IDs",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				values, err := client.FindPowerShelfRackIDs(ctx, ids)
				return len(values), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.shelfBatches },
		},
		{
			name: "power shelf controller states",
			invoke: func(ctx context.Context, client *grpcClient, ids []string) (int, error) {
				values, err := client.FindPowerShelfControllerStates(ctx, ids)
				return len(values), err
			},
			batchCalls: func(fake *recordingForgeClient) [][]string { return fake.shelfBatches },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &recordingForgeClient{
				runtimeConfig: &corev1.RuntimeConfig{MaxFindByIds: 2},
				machineIDs:    ids,
			}
			count, err := test.invoke(context.Background(), newRecordingGRPCClient(fake), ids)

			require.NoError(t, err)
			assert.Equal(t, len(ids), count)
			assert.Equal(t, expectedBatches, test.batchCalls(fake))
			require.Len(t, fake.versionRequests, 1)
			assert.True(t, fake.versionRequests[0].GetDisplayConfig())
		})
	}
}

func TestGrpcClient_ByIDLookupsTreatZeroOrAbsentLimitAsUnlimited(t *testing.T) {
	ids := []string{"a", "b", "c"}
	tests := []struct {
		name   string
		config *corev1.RuntimeConfig
	}{
		{name: "zero", config: &corev1.RuntimeConfig{MaxFindByIds: 0}},
		{name: "absent", config: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &recordingForgeClient{runtimeConfig: test.config}
			result, err := newRecordingGRPCClient(fake).FindSwitchRackIDs(context.Background(), ids)

			require.NoError(t, err)
			assert.Len(t, result, len(ids))
			assert.Equal(t, [][]string{ids}, fake.switchBatches)
		})
	}
}

func TestGrpcClient_ByIDLookupsRejectPartialResults(t *testing.T) {
	ids := []string{"a", "b", "c", "d"}
	tests := []struct {
		name        string
		fake        *recordingForgeClient
		errorString string
	}{
		{
			name: "runtime config lookup fails",
			fake: &recordingForgeClient{
				versionErr: errors.New("injected Version failure"),
			},
			errorString: "injected Version failure",
		},
		{
			name: "batch RPC fails",
			fake: &recordingForgeClient{
				runtimeConfig: &corev1.RuntimeConfig{MaxFindByIds: 2},
				failCall:      2,
			},
			errorString: "injected switch lookup failure",
		},
		{
			name: "batch response is incomplete",
			fake: &recordingForgeClient{
				runtimeConfig: &corev1.RuntimeConfig{MaxFindByIds: 2},
				omitID:        "c",
			},
			errorString: "incomplete response; missing IDs: c",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := newRecordingGRPCClient(test.fake).FindSwitchRackIDs(context.Background(), ids)

			require.Error(t, err)
			assert.ErrorContains(t, err, test.errorString)
			assert.Nil(t, result)
		})
	}
}
