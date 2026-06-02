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
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
)

// Default polling parameters for the rack-assignment safety check. They are
// chosen to err on the side of waiting: 30 minutes is long enough to cover a
// running tenant terminate cycle, and 60s keeps the gRPC load on Core low.
const (
	DefaultAssignmentWaitTimeout  = 30 * time.Minute
	DefaultAssignmentPollInterval = 60 * time.Second

	// assignedStatePrefix matches Core's `ManagedHostState::Assigned/...`
	// Display form (e.g. "Assigned/Provisioning", "Assigned/Reprovision/...").
	// It is intentionally a prefix and not Contains, so "PreAssignedMeasuring"
	// / "PostAssignedMeasuring" — which are early/late attestation phases
	// distinct from "host has an instance attached" — are not flagged.
	assignedStatePrefix = "Assigned/"
)

// AssignmentChecker waits until no compute machines in a given scope are in
// Core's `Assigned/...` state, guarding power and firmware operations from
// running while a tenant is actively using the hardware.
type AssignmentChecker struct {
	client       nicoapi.Client
	timeout      time.Duration
	pollInterval time.Duration
}

// NewAssignmentChecker builds an AssignmentChecker with the supplied NICo
// client. Zero or negative timeout/interval values fall back to the package
// defaults so callers can opt in to overrides without having to repeat them.
func NewAssignmentChecker(client nicoapi.Client, timeout, pollInterval time.Duration) *AssignmentChecker {
	if timeout <= 0 {
		timeout = DefaultAssignmentWaitTimeout
	}
	if pollInterval <= 0 {
		pollInterval = DefaultAssignmentPollInterval
	}
	return &AssignmentChecker{
		client:       client,
		timeout:      timeout,
		pollInterval: pollInterval,
	}
}

// IsAssignedState reports whether the given Machine.state string from Core
// represents the `Assigned` host lifecycle. Exported so callers (e.g. tests)
// can share the canonical predicate.
func IsAssignedState(state string) bool {
	return strings.HasPrefix(state, assignedStatePrefix)
}

// WaitForMachinesUnassigned blocks until every machine in machineIDs has left
// the `Assigned/...` state, or until the configured timeout elapses. An empty
// list is a no-op. A nil client also short-circuits to no-op so unit tests can
// construct managers without a NICo dependency.
func (c *AssignmentChecker) WaitForMachinesUnassigned(ctx context.Context, machineIDs []string) error {
	if c == nil || c.client == nil || len(machineIDs) == 0 {
		return nil
	}

	uniqueIDs := dedupSorted(machineIDs)

	deadline := time.Now().Add(c.timeout)
	attempt := 0
	for {
		attempt++
		assigned, err := c.findAssigned(ctx, uniqueIDs)
		if err != nil {
			return fmt.Errorf("assignment check failed: %w", err)
		}
		if len(assigned) == 0 {
			if attempt > 1 {
				log.Info().
					Strs("machine_ids", uniqueIDs).
					Int("attempts", attempt).
					Msg("Machines left Assigned state, proceeding with operation")
			}
			return nil
		}

		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"timed out after %s waiting for machines to leave Assigned state: %s",
				c.timeout, strings.Join(assigned, ", "),
			)
		}

		log.Info().
			Strs("assigned_machine_ids", assigned).
			Dur("poll_interval", c.pollInterval).
			Time("deadline", deadline).
			Msg("Machines still Assigned, deferring operation")

		sleepErr := sleep(ctx, c.pollInterval)
		if sleepErr != nil {
			return sleepErr
		}
	}
}

// WaitForRacksUnassigned resolves each rackID to its host machines and then
// delegates to WaitForMachinesUnassigned. Duplicate rack IDs are coalesced so
// a multi-component target on a single rack only triggers one rack lookup.
func (c *AssignmentChecker) WaitForRacksUnassigned(ctx context.Context, rackIDs []string) error {
	if c == nil || c.client == nil || len(rackIDs) == 0 {
		return nil
	}

	uniqueRacks := dedupSorted(rackIDs)

	allMachines := make([]string, 0)
	for _, rackID := range uniqueRacks {
		machines, err := c.client.FindHostMachineIdsByRack(ctx, rackID)
		if err != nil {
			return fmt.Errorf("list host machines for rack %s: %w", rackID, err)
		}
		allMachines = append(allMachines, machines...)
	}

	if len(allMachines) == 0 {
		// No host machines on these racks (e.g., switch-only rack or empty
		// rack). The safety check is therefore vacuously satisfied; log so
		// the absence is visible.
		log.Info().
			Strs("rack_ids", uniqueRacks).
			Msg("Rack assignment check: no host machines found, skipping wait")
		return nil
	}

	return c.WaitForMachinesUnassigned(ctx, allMachines)
}

// findAssigned returns the subset of machineIDs that Core currently reports in
// the `Assigned/...` state. Machines whose state cannot be retrieved are NOT
// treated as Assigned — that would conflate "missing data" with "in use" and
// fail-closed on every transient gRPC blip. The caller logs which IDs returned
// no data so the gap stays visible.
func (c *AssignmentChecker) findAssigned(ctx context.Context, machineIDs []string) ([]string, error) {
	details, err := c.client.FindMachinesByIds(ctx, machineIDs)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]nicoapi.MachineDetail, len(details))
	for _, d := range details {
		byID[d.MachineID] = d
	}

	var assigned []string
	var missing []string
	for _, id := range machineIDs {
		d, ok := byID[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		if IsAssignedState(d.State) {
			assigned = append(assigned, id)
		}
	}

	if len(missing) > 0 {
		log.Warn().
			Strs("missing_machine_ids", missing).
			Msg("Assignment check: Core returned no state for some machines, treating them as unassigned")
	}
	return assigned, nil
}

// sleep returns context.Canceled (or context.DeadlineExceeded) immediately if
// the context is cancelled before the duration elapses, instead of sleeping
// the full interval and then noticing. Using time.NewTimer (not time.After)
// avoids leaking the underlying timer if the context wins the race.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return errors.Join(errors.New("aborted while waiting for machines to leave Assigned state"), ctx.Err())
	case <-t.C:
		return nil
	}
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
