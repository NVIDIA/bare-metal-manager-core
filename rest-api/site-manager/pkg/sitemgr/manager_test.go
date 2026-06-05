// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitemgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManager(t *testing.T) {
	s, err := TestManagerCreateSite()
	assert.Nil(t, err)
	assert.NotNil(t, s)
	err = s.TestManagerSiteTest()
	assert.NotNil(t, err)
	s.Teardown()
}

func TestCLI(t *testing.T) {
	cmd := NewCommand()
	assert.NotEqual(t, nil, cmd)
}
