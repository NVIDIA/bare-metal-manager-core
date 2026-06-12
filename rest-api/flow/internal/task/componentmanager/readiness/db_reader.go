// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package readiness

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/devicetypes"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

// DBReader is the production StatusReader. It reads the component table
// via the supplied bun.IDB and exposes only the columns the gate needs.
type DBReader struct {
	idb bun.IDB
}

// NewDBReader builds a StatusReader backed by the given bun.IDB.
func NewDBReader(idb bun.IDB) *DBReader {
	return &DBReader{idb: idb}
}

// GetStatusesByExternalIDs implements StatusReader. The map key is the
// external_id string as supplied by the caller — components without a
// matching row (or with a NULL status) are simply absent.
func (r *DBReader) GetStatusesByExternalIDs(ctx context.Context, externalIDs []string) (map[string]*types.ComponentOperationStatus, error) {
	if len(externalIDs) == 0 {
		return map[string]*types.ComponentOperationStatus{}, nil
	}

	type row struct {
		bun.BaseModel `bun:"table:component,alias:c"`
		ExternalID    string                          `bun:"external_id"`
		Status        *types.ComponentOperationStatus `bun:"status"`
	}

	var rows []row
	err := r.idb.NewSelect().
		Model((*row)(nil)).
		Column("external_id", "status").
		Where("external_id IN (?)", bun.In(externalIDs)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("select component statuses: %w", err)
	}

	out := make(map[string]*types.ComponentOperationStatus, len(rows))
	for _, r := range rows {
		out[r.ExternalID] = r.Status
	}
	return out, nil
}

// GetHostExternalIDsByRackIDs implements StatusReader.
//
// Rack IDs are Core UUIDs as strings (component.rack_id stores the same
// UUID Core uses). Strings that fail UUID parsing are silently dropped —
// they cannot match any row, so we don't bother surfacing an error for
// what is almost certainly an upstream typo.
func (r *DBReader) GetHostExternalIDsByRackIDs(ctx context.Context, rackIDs []string) (map[string][]string, error) {
	if len(rackIDs) == 0 {
		return map[string][]string{}, nil
	}

	parsed := make([]uuid.UUID, 0, len(rackIDs))
	rackByUUID := make(map[uuid.UUID]string, len(rackIDs))
	for _, s := range rackIDs {
		u, err := uuid.Parse(s)
		if err != nil {
			continue
		}
		parsed = append(parsed, u)
		rackByUUID[u] = s
	}
	if len(parsed) == 0 {
		return map[string][]string{}, nil
	}

	type row struct {
		bun.BaseModel `bun:"table:component,alias:c"`
		ExternalID    string    `bun:"external_id"`
		RackID        uuid.UUID `bun:"rack_id"`
	}

	var rows []row
	err := r.idb.NewSelect().
		Model((*row)(nil)).
		Column("external_id", "rack_id").
		Where("rack_id IN (?)", bun.In(parsed)).
		Where("type = ?", devicetypes.ComponentTypeToString(devicetypes.ComponentTypeCompute)).
		Where("external_id IS NOT NULL AND external_id != ''").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("select host components by rack: %w", err)
	}

	out := make(map[string][]string, len(rackIDs))
	for _, r := range rows {
		key, ok := rackByUUID[r.RackID]
		if !ok {
			continue
		}
		out[key] = append(out[key], r.ExternalID)
	}
	return out, nil
}

var _ StatusReader = (*DBReader)(nil)
