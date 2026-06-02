/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nico

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
)

func TestIsAssignedState(t *testing.T) {
	cases := map[string]bool{
		"Assigned/Provisioning":              true,
		"Assigned/Reprovision/Init":          true,
		"Assigned/":                          true,
		"Ready":                              false,
		"":                                   false,
		"PreAssignedMeasuring/PollResult":    false,
		"PostAssignedMeasuring/MeasuredBoot": false,
		"HostInitializing/Init":              false,
		// Defensive: a literal "Assigned" without the trailing slash is not
		// a state Core emits today (Display always writes "Assigned/...").
		// Keep this here so the predicate stays strict; flipping it later
		// would silently change the contract for the safety check.
		"Assigned": false,
	}
	for input, want := range cases {
		assert.Equalf(t, want, IsAssignedState(input), "state=%q", input)
	}
}

func TestWaitForMachinesUnassigned_NoMachines_ShortCircuits(t *testing.T) {
	c := NewAssignmentChecker(nicoapi.NewMockClient(), time.Second, 10*time.Millisecond)
	require.NoError(t, c.WaitForMachinesUnassigned(context.Background(), nil))
	require.NoError(t, c.WaitForMachinesUnassigned(context.Background(), []string{}))
}

func TestWaitForMachinesUnassigned_NilClient_ShortCircuits(t *testing.T) {
	c := NewAssignmentChecker(nil, time.Second, 10*time.Millisecond)
	require.NoError(t, c.WaitForMachinesUnassigned(context.Background(), []string{"m1"}))
}

func TestWaitForMachinesUnassigned_AlreadyReady(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m1", State: "Ready"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m2", State: "HostInitializing/Init"})

	c := NewAssignmentChecker(client, time.Second, 10*time.Millisecond)
	require.NoError(t, c.WaitForMachinesUnassigned(context.Background(), []string{"m1", "m2"}))
}

func TestWaitForMachinesUnassigned_TimesOutWhileAssigned(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m1", State: "Assigned/Provisioning"})

	c := NewAssignmentChecker(client, 50*time.Millisecond, 10*time.Millisecond)
	err := c.WaitForMachinesUnassigned(context.Background(), []string{"m1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Contains(t, err.Error(), "m1")
}

// TestWaitForMachinesUnassigned_MissingTreatedAsUnassigned encodes the
// deliberate fail-open behaviour: if Core has no record of a machine, we let
// the operation proceed rather than block on indefinite missing data.
func TestWaitForMachinesUnassigned_MissingTreatedAsUnassigned(t *testing.T) {
	client := nicoapi.NewMockClient()
	// Intentionally do not register "m-missing".
	c := NewAssignmentChecker(client, 100*time.Millisecond, 10*time.Millisecond)
	require.NoError(t, c.WaitForMachinesUnassigned(context.Background(), []string{"m-missing"}))
}

func TestWaitForRacksUnassigned_ResolvesMachinesAndPasses(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m-A1", State: "Ready"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m-A2", State: "Ready"})
	client.SetRackHostMachineIDs("rack-A", []string{"m-A1", "m-A2"})

	c := NewAssignmentChecker(client, time.Second, 10*time.Millisecond)
	require.NoError(t, c.WaitForRacksUnassigned(context.Background(), []string{"rack-A"}))
}

func TestWaitForRacksUnassigned_BlocksOnAssignedHost(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m-A1", State: "Ready"})
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m-A2", State: "Assigned/Provisioning"})
	client.SetRackHostMachineIDs("rack-A", []string{"m-A1", "m-A2"})

	c := NewAssignmentChecker(client, 50*time.Millisecond, 10*time.Millisecond)
	err := c.WaitForRacksUnassigned(context.Background(), []string{"rack-A"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Contains(t, err.Error(), "m-A2")
}

func TestWaitForRacksUnassigned_EmptyRackPasses(t *testing.T) {
	client := nicoapi.NewMockClient()
	// Rack-B has no host machines registered (switch-only rack).
	c := NewAssignmentChecker(client, time.Second, 10*time.Millisecond)
	require.NoError(t, c.WaitForRacksUnassigned(context.Background(), []string{"rack-B"}))
}

func TestWaitForRacksUnassigned_ContextCancellationStopsPolling(t *testing.T) {
	client := nicoapi.NewMockClient()
	client.AddMachine(nicoapi.MachineDetail{MachineID: "m1", State: "Assigned/Provisioning"})
	client.SetRackHostMachineIDs("rack-A", []string{"m1"})

	// Long timeout, but the context is cancelled after the first poll —
	// we should return promptly with the context error wrapped, not after
	// the full assignment timeout.
	c := NewAssignmentChecker(client, time.Hour, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := c.WaitForRacksUnassigned(ctx, []string{"rack-A"})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Less(t, elapsed, time.Second, "cancellation should abort the poll quickly")
}
