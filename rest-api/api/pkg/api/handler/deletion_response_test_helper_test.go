// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
)

func assertDeletionAcceptedResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp model.APIDeletionAcceptedResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, model.DeletionRequestAcceptedMessage, resp.Message)
}
