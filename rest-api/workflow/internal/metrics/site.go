// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// SiteInventoryReceipt is one Site's most recent Machine inventory arrival.
// Received is nil for a Registered Site that has never delivered inventory.
type SiteInventoryReceipt struct {
	SiteID   uuid.UUID
	SiteName string
	Received *time.Time
}

// SiteInventoryMetrics publishes Machine inventory freshness per Site.
type SiteInventoryMetrics struct {
	lastReceipt *prometheus.GaugeVec
}

// SetLastInventoryReceipts republishes the last Machine inventory receipt time
// for every Registered Site, as a Unix timestamp that operators compare against
// time(). A Site that has never delivered inventory reports 0 rather than no
// series at all, so a Site that never connects is as visible as one that stops.
//
// The whole vector is rebuilt from the caller's set on each cycle. Without that,
// a deleted or de-registered Site would keep its last value and age into an
// alert nothing can clear.
func (sim *SiteInventoryMetrics) SetLastInventoryReceipts(receipts []SiteInventoryReceipt) {
	// Nil when the worker was built with metrics disabled, and in activity tests.
	if sim == nil {
		return
	}

	sim.lastReceipt.Reset()

	for _, receipt := range receipts {
		seconds := float64(0)
		if receipt.Received != nil {
			seconds = float64(receipt.Received.Unix())
		}
		sim.lastReceipt.WithLabelValues(receipt.SiteName, receipt.SiteID.String()).Set(seconds)
	}
}

// NewSiteInventoryMetrics initializes Site inventory freshness metrics
func NewSiteInventoryMetrics(reg prometheus.Registerer) *SiteInventoryMetrics {
	siteInventoryMetrics := &SiteInventoryMetrics{
		lastReceipt: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "site_last_inventory_receipt_timestamp_seconds",
				Help:      "Unix timestamp of the last Machine inventory received from a Registered Site, or 0 if none has been received",
			},
			[]string{"site", "site_id"}),
	}
	reg.MustRegister(siteInventoryMetrics.lastReceipt)

	return siteInventoryMetrics
}
