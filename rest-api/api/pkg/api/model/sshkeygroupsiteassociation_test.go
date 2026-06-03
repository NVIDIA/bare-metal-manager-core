// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
)

func TestNewAPISSHKeyGroupSiteAssociation(t *testing.T) {
	skgsa := cdbm.SSHKeyGroupSiteAssociation{
		ID:            uuid.New(),
		SSHKeyGroupID: uuid.New(),
		SiteID:        uuid.New(),
		Version:       cutil.GetPtr("1234"),
		Status:        cdbm.SSHKeyGroupSiteAssociationStatusSyncing,
		Created:       time.Now(),
		Updated:       time.Now(),
	}
	apiskgsa := NewAPISSHKeyGroupSiteAssociation(&skgsa, nil)
	assert.Equal(t, apiskgsa.ControllerKeySetVersion, skgsa.Version)
	assert.Equal(t, apiskgsa.Status, skgsa.Status)
}
