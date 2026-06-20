// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIDeletionAcceptedResponse_JSON(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(NewAPIDeletionAcceptedResponse())
	require.NoError(t, err)
	assert.JSONEq(t, `{"message":"`+DeletionRequestAcceptedMessage+`"}`, string(payload))

	var decoded APIDeletionAcceptedResponse
	require.NoError(t, json.Unmarshal(payload, &decoded))
	assert.Equal(t, DeletionRequestAcceptedMessage, decoded.Message)
}
