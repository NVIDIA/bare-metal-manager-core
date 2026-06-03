// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// ComponentFilterKind discriminates the two variants of ComponentFilter.
type ComponentFilterKind string

const (
	// ComponentFilterKindTypes filters by component type (e.g. COMPUTE, POWERSHELF).
	ComponentFilterKindTypes ComponentFilterKind = "types"
	// ComponentFilterKindComponents targets specific components by their UUIDs.
	ComponentFilterKindComponents ComponentFilterKind = "components"
)

// ComponentFilter is the discriminated union stored in component_filter JSONB.
// Exactly one of Types or Components must be non-nil; Kind is always set.
type ComponentFilter struct {
	Kind ComponentFilterKind `json:"kind"`
	// Types lists the component type strings when Kind == "types".
	Types []string `json:"types,omitempty"`
	// Components lists the component UUIDs when Kind == "components".
	Components []uuid.UUID `json:"components,omitempty"`
}

// validate checks the discriminated-union invariants of a ComponentFilter.
// It is called by both MarshalComponentFilter and UnmarshalComponentFilter so
// that invalid states can neither be written to nor read from the database.
func (cf *ComponentFilter) validate() error {
	switch cf.Kind {
	case ComponentFilterKindTypes:
		if len(cf.Types) == 0 {
			return fmt.Errorf(
				"component filter kind %q requires at least one type",
				cf.Kind,
			)
		}
		if len(cf.Components) > 0 {
			return fmt.Errorf(
				"component filter kind %q must not have components set",
				cf.Kind,
			)
		}
	case ComponentFilterKindComponents:
		if len(cf.Components) == 0 {
			return fmt.Errorf(
				"component filter kind %q requires at least one component",
				cf.Kind,
			)
		}
		if len(cf.Types) > 0 {
			return fmt.Errorf(
				"component filter kind %q must not have types set", cf.Kind,
			)
		}
	default:
		return fmt.Errorf("unknown component filter kind: %q", cf.Kind)
	}

	return nil
}

// MarshalComponentFilter marshals a ComponentFilter to JSON for JSONB storage.
func MarshalComponentFilter(cf *ComponentFilter) (json.RawMessage, error) {
	if cf == nil {
		return nil, nil
	}

	if err := cf.validate(); err != nil {
		return nil, err
	}

	if cf.Kind == ComponentFilterKindTypes {
		for _, t := range cf.Types {
			if !devicetypes.IsValidComponentTypeString(t) {
				return nil, fmt.Errorf(
					"component filter kind %q contains unknown type %q",
					cf.Kind, t,
				)
			}
		}
	}

	return json.Marshal(cf)
}

// isNullFilter reports whether raw represents the "no filter" state.
// UnmarshalComponentFilter treats nil, empty, and the JSON null literal as
// equivalent; ComponentFilterEqual must use the same definition.
func isNullFilter(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || string(trimmed) == "null"
}

// ComponentFilterEqual reports whether two component_filter JSONB values are
// semantically equivalent. nil, empty, and the JSON null literal are all
// treated as equivalent (they all mean "all components"). For type-based
// filters, element order is ignored.
func ComponentFilterEqual(a, b json.RawMessage) (bool, error) {
	// Quick checks that avoid unmarshaling.
	aNull, bNull := isNullFilter(a), isNullFilter(b)
	if aNull && bNull {
		return true, nil // both "all components"
	}
	if aNull != bNull {
		return false, nil // one null, one not — never equal
	}
	if bytes.Equal(a, b) {
		return true, nil // byte-identical — no parse needed
	}

	cfA, err := UnmarshalComponentFilter(a)
	if err != nil {
		return false, fmt.Errorf("unmarshal component filter: %w", err)
	}
	cfB, err := UnmarshalComponentFilter(b)
	if err != nil {
		return false, fmt.Errorf("unmarshal component filter: %w", err)
	}

	if cfA == nil && cfB == nil {
		return true, nil
	}
	if cfA == nil || cfB == nil {
		return false, nil
	}
	if cfA.Kind != cfB.Kind {
		return false, nil
	}

	switch cfA.Kind {
	case ComponentFilterKindTypes:
		return sliceSetEqual(cfA.Types, cfB.Types), nil
	case ComponentFilterKindComponents:
		return sliceSetEqual(cfA.Components, cfB.Components), nil
	}
	return false, nil
}

// sliceSetEqual reports whether a and b contain the same elements regardless
// of order. Duplicate elements are counted, so [A, A, B] != [A, B, B].
func sliceSetEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	counts := make(map[T]int, len(a))
	for _, v := range a {
		counts[v]++
	}

	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}

	return true
}

// UnmarshalComponentFilter parses a JSONB value into a ComponentFilter.
// Returns nil if raw is nil, empty, or the JSON null literal — all three
// representations mean "no filter" (target all components in the rack).
// The JSON null case arises when bun's AppendJSONValue serialises a nil
// json.RawMessage for a jsonb-typed column without the nullzero tag.
func UnmarshalComponentFilter(raw json.RawMessage) (*ComponentFilter, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}

	var cf ComponentFilter
	if err := json.Unmarshal(trimmed, &cf); err != nil {
		return nil, err
	}

	if err := cf.validate(); err != nil {
		return nil, err
	}

	return &cf, nil
}

// TaskScheduleScope is the bun model for the task_schedule_scope table.
// Each row represents one rack target in a schedule's scope.
// LastTaskID tracks the task produced for this rack by the most recent firing,
// used by the overlap check to determine whether the previous execution is still active.
//
// Invariant: when ComponentFilter has kind "components", every UUID listed
// in that filter must belong to RackID. This is enforced by the API write
// path (resolveComponentScope groups components by rack before persisting).
// At fire time the dispatcher sets RequiredRackID on the SubmitTask request,
// so any violation caused by a direct DB modification (e.g. a component moved
// to a different rack) is detected before any task is created, and the scope
// is skipped with an error.
type TaskScheduleScope struct {
	bun.BaseModel `bun:"table:task_schedule_scope,alias:tss"`

	ID              uuid.UUID       `bun:"id,pk,type:uuid,default:gen_random_uuid()"`
	ScheduleID      uuid.UUID       `bun:"schedule_id,type:uuid,notnull"`
	RackID          uuid.UUID       `bun:"rack_id,type:uuid,notnull"`
	ComponentFilter json.RawMessage `bun:"component_filter,type:jsonb,nullzero"`
	LastTaskID      *uuid.UUID      `bun:"last_task_id,type:uuid"`
	CreatedAt       time.Time       `bun:"created_at,notnull,default:current_timestamp"`
}
