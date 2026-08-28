// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

const (
	// InventoryStatusSuccess workflow has completed successfully
	InventoryStatusSuccess = "Success"
	// InventoryStatusFailed workflow activity execution has failed
	InventoryStatusFailed = "Failed"

	// Inventory operation types for metrics labels
	InventoryOperationTypeCreate = "create"
	InventoryOperationTypeDelete = "delete"
)

// InventoryObjectLifecycleEvent represents a lifecycle event for an inventory object.
// Either Created or Deleted should be set, but not both:
// - For CREATE events: Created should be non-nil, Deleted should be nil
// - For DELETE events: Deleted should be non-nil, Created should be nil
type InventoryObjectLifecycleEvent struct {
	ObjectID uuid.UUID
	Created  *time.Time // Non-nil for CREATE events, nil for DELETE events
	Deleted  *time.Time // Non-nil for DELETE events, nil for CREATE events
}

// ManageInventoryMetrics is a wrapper for managing inventory metrics activities
type ManageInventoryMetrics struct {
	dbSession *cdb.Session
	latency   *prometheus.HistogramVec

	// The worker runs activities concurrently against one registered instance,
	// so every access to the Site name cache below has to hold siteIDNameMutex.
	// An unsynchronized map here is a concurrent write that kills the process.
	siteIDNameMutex sync.RWMutex
	siteIDNameMap   map[uuid.UUID]string
}

// RecordLatency is a Temporal activity that records the latency of inventory processing activities
func (mim *ManageInventoryMetrics) RecordLatency(ctx context.Context, siteID uuid.UUID, activity string, isFailed bool, duration time.Duration) error {
	// This method is called by inventory workflows
	// NOTE: Temporal will cache the arguments to this call, even if this activity is scheduled a bit later, we'll still get the correct latency
	status := InventoryStatusSuccess
	if isFailed {
		status = InventoryStatusFailed
	}

	siteName, err := mim.getSiteName(ctx, siteID)
	if err != nil {
		return err
	}

	mim.latency.WithLabelValues(siteName, activity, status).Observe(duration.Seconds())

	return nil
}

// getSiteName resolves a Site name, caching it to avoid a DB read per inventory
// call. Concurrent callers may both miss and read the same Site; that costs a
// duplicate query rather than holding the write lock across the DB call.
func (mim *ManageInventoryMetrics) getSiteName(ctx context.Context, siteID uuid.UUID) (string, error) {
	mim.siteIDNameMutex.RLock()
	siteName, ok := mim.siteIDNameMap[siteID]
	mim.siteIDNameMutex.RUnlock()
	if ok {
		return siteName, nil
	}

	siteDAO := cdbm.NewSiteDAO(mim.dbSession)
	site, err := siteDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		return "", err
	}

	mim.siteIDNameMutex.Lock()
	mim.siteIDNameMap[siteID] = site.Name
	mim.siteIDNameMutex.Unlock()

	return site.Name, nil
}

// InitInventoryMetrics initializes inventory activity metrics
func NewManageInventoryMetrics(reg prometheus.Registerer, dbSession *cdb.Session) *ManageInventoryMetrics {
	inventoryMetrics := &ManageInventoryMetrics{
		dbSession: dbSession,
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: MetricsNamespace,
				Name:      "inventory_latency_seconds",
				Help:      "Latency of each inventory call",
				// The top buckets reach the inventory activities' StartToCloseTimeout.
				// Stopping short of it puts every degraded call in +Inf, which is where
				// a quantile stops being computable.
				Buckets: []float64{0.0005, 0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0},
			},
			[]string{"site", "activity", "status"}),

		siteIDNameMap: map[uuid.UUID]string{},
	}
	reg.MustRegister(inventoryMetrics.latency)

	return inventoryMetrics
}
