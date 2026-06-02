// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
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
	dbSession     *cdb.Session
	latency       *prometheus.HistogramVec
	siteIDNameMap map[uuid.UUID]string
}

// RecordLatency is a Temporal activity that records the latency of inventory processing activities
func (mim *ManageInventoryMetrics) RecordLatency(ctx context.Context, siteID uuid.UUID, activity string, isFailed bool, duration time.Duration) error {
	// This method is called by inventory workflows
	// NOTE: Temporal will cache the arguments to this call, even if this activity is scheduled a bit later, we'll still get the correct latency
	status := InventoryStatusSuccess
	if isFailed {
		status = InventoryStatusFailed
	}

	// Cache site name to avoid repeated DB call
	siteName, ok := mim.siteIDNameMap[siteID]
	if !ok {
		siteDAO := cdbm.NewSiteDAO(mim.dbSession)
		site, err := siteDAO.GetByID(context.Background(), nil, siteID, nil, false)
		if err != nil {
			return err
		}
		siteName = site.Name
		mim.siteIDNameMap[siteID] = siteName
	}

	mim.latency.WithLabelValues(siteName, activity, status).Observe(duration.Seconds())

	return nil
}

// InitInventoryMetrics initializes inventory activity metrics
func NewManageInventoryMetrics(reg prometheus.Registerer, dbSession *cdb.Session) ManageInventoryMetrics {
	inventoryMetrics := ManageInventoryMetrics{
		dbSession: dbSession,
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: MetricsNamespace,
				Name:      "inventory_latency_seconds",
				Help:      "Latency of each inventory call",
				Buckets:   []float64{0.0005, 0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0},
			},
			[]string{"site", "activity", "status"}),

		siteIDNameMap: map[uuid.UUID]string{},
	}
	reg.MustRegister(inventoryMetrics.latency)

	return inventoryMetrics
}
