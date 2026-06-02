// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/stretchr/testify/assert"

	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"
)

func TestManageInventoryMetrics_RecordLatency(t *testing.T) {
	dbSession := util.TestInitDB(t)
	defer dbSession.Close()

	util.TestSetupSchema(t, dbSession)

	ipOrg := "test-provider-org"
	ipRoles := []string{"FORGE_PROVIDER_ADMIN"}

	ipu := util.TestBuildUser(t, dbSession, uuid.NewString(), []string{ipOrg}, ipRoles)
	ip := util.TestBuildInfrastructureProvider(t, dbSession, "test-provider", ipOrg, ipu)

	site := util.TestBuildSite(t, dbSession, ip, "test-site-1", cdbm.SiteStatusRegistered, nil, ipu)
	assert.NotNil(t, site)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())

	inventoryMetricsManager := NewManageInventoryMetrics(reg, dbSession)

	err := inventoryMetricsManager.RecordLatency(context.Background(), site.ID, "test-workflow", false, time.Second)
	assert.NoError(t, err)

	metrics, err := reg.Gather()
	assert.NoError(t, err)
	assert.Equal(t, "test-workflow", *metrics[0].Metric[0].Label[0].Value)
	assert.Equal(t, site.Name, *metrics[0].Metric[0].Label[1].Value)
	assert.Equal(t, InventoryStatusSuccess, *metrics[0].Metric[0].Label[2].Value)

	assert.Equal(t, 1, len(inventoryMetricsManager.siteIDNameMap))
}
