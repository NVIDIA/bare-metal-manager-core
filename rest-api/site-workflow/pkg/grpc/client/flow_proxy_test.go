// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveFlowMethod(t *testing.T) {
	md, err := resolveFlowMethod("Version")
	require.NoError(t, err)
	assert.Equal(t, "Version", string(md.Name()))

	md, err = resolveFlowMethod("/v1.Flow/CreateOperationRun")
	require.NoError(t, err)
	assert.Equal(t, "CreateOperationRun", string(md.Name()))

	_, err = resolveFlowMethod("DefinitelyNotARealMethod")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownFlowMethod))
}

func TestInvokeFlowJSONConn(t *testing.T) {
	t.Run("round trips request and response", func(t *testing.T) {
		conn := &fakeProxyConn{setValue: "proxy-test-value"}
		respJSON, err := invokeFlowJSONConn(context.Background(), conn, "Version", nil)
		require.NoError(t, err)
		assert.Equal(t, "/v1.Flow/Version", conn.lastMethod)
		assert.Contains(t, string(respJSON), "proxy-test-value")
	})

	t.Run("rejects unknown method before dialing", func(t *testing.T) {
		conn := &fakeProxyConn{}
		_, err := invokeFlowJSONConn(context.Background(), conn, "NopeNotReal", nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnknownFlowMethod))
		assert.Empty(t, conn.lastMethod, "transport must not be invoked for an unknown method")
	})
}

func TestFlowMethodName(t *testing.T) {
	assert.Equal(t, "CreateOperationRun", flowMethodName("/v1.Flow/CreateOperationRun"))
	assert.Equal(t, "CreateOperationRun", flowMethodName("CreateOperationRun"))
	assert.Equal(t, "/v1.Flow/CreateOperationRun", flowFullMethod("CreateOperationRun"))
	assert.True(t, strings.HasPrefix(flowFullMethod("Version"), "/v1.Flow/"))
}
