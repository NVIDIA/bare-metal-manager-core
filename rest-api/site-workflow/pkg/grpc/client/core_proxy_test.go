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
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fakeProxyConn implements grpc.ClientConnInterface for transcoder tests. It
// records the invoked method and populates the first scalar string field of the
// reply so the response-encoding path runs without a real server.
type fakeProxyConn struct {
	lastMethod string
	setValue   string
}

func (f *fakeProxyConn) Invoke(_ context.Context, method string, _, reply any, _ ...grpc.CallOption) error {
	f.lastMethod = method
	msg, ok := reply.(proto.Message)
	if !ok {
		return errors.New("reply is not a proto.Message")
	}
	pm := msg.ProtoReflect()
	fields := pm.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Kind() == protoreflect.StringKind && fd.Cardinality() != protoreflect.Repeated {
			pm.Set(fd, protoreflect.ValueOfString(f.setValue))
			break
		}
	}
	return nil
}

func (f *fakeProxyConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("streaming not supported")
}

func TestResolveForgeMethod(t *testing.T) {
	md, err := resolveForgeMethod("Version")
	require.NoError(t, err)
	assert.Equal(t, "Version", string(md.Name()))

	md, err = resolveForgeMethod("/forge.Forge/CreateCredential")
	require.NoError(t, err)
	assert.Equal(t, "CreateCredential", string(md.Name()))

	_, err = resolveForgeMethod("DefinitelyNotARealMethod")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownCoreMethod))
}

func TestInvokeJSONConn(t *testing.T) {
	t.Run("round trips request and response", func(t *testing.T) {
		conn := &fakeProxyConn{setValue: "proxy-test-value"}
		respJSON, err := invokeJSONConn(context.Background(), conn, "Version", nil)
		require.NoError(t, err)
		assert.Equal(t, "/forge.Forge/Version", conn.lastMethod)
		assert.Contains(t, string(respJSON), "proxy-test-value")
	})

	t.Run("rejects unknown method before dialing", func(t *testing.T) {
		conn := &fakeProxyConn{}
		_, err := invokeJSONConn(context.Background(), conn, "NopeNotReal", nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnknownCoreMethod))
		assert.Empty(t, conn.lastMethod, "transport must not be invoked for an unknown method")
	})
}

func TestCoreMethodName(t *testing.T) {
	assert.Equal(t, "CreateCredential", coreMethodName("/forge.Forge/CreateCredential"))
	assert.Equal(t, "CreateCredential", coreMethodName("CreateCredential"))
	assert.Equal(t, "/forge.Forge/CreateCredential", coreFullMethod("CreateCredential"))
	assert.True(t, strings.HasPrefix(coreFullMethod("Version"), "/forge.Forge/"))
}
