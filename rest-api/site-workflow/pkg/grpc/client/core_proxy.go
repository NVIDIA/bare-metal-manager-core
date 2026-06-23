// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"path"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// coreServiceName is the fully qualified NICo Core gRPC service. Its descriptors
// are registered in this binary because this package imports the generated
// forge bindings (see core_client.go), so they can be resolved at runtime.
const coreServiceName = "forge.Forge"

// ErrUnknownCoreMethod is returned when a method name does not resolve to a
// unary RPC on the forge.Forge service.
var ErrUnknownCoreMethod = errors.New("unknown NICo Core method")

// coreMethodName returns the bare method name for a bare or fully qualified
// gRPC method ("/forge.Forge/CreateCredential" -> "CreateCredential").
func coreMethodName(method string) string {
	return path.Base(method)
}

// coreFullMethod returns the canonical "/forge.Forge/<Method>" gRPC path.
func coreFullMethod(method string) string {
	return "/" + coreServiceName + "/" + coreMethodName(method)
}

func resolveForgeMethod(method string) (protoreflect.MethodDescriptor, error) {
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(coreServiceName))
	if err != nil {
		return nil, fmt.Errorf("resolve service %q: %w", coreServiceName, err)
	}
	svc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is not a gRPC service", coreServiceName)
	}
	md := svc.Methods().ByName(protoreflect.Name(coreMethodName(method)))
	if md == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCoreMethod, coreMethodName(method))
	}
	if md.IsStreamingClient() || md.IsStreamingServer() {
		return nil, fmt.Errorf("method %q is streaming and not supported by the proxy", md.Name())
	}
	return md, nil
}

// InvokeJSON proxies a unary forge.Forge call: it transcodes reqJSON (protojson)
// into the request message for method, invokes it on the Core connection, and
// returns the protojson-encoded response. An empty reqJSON is treated as the
// zero-valued request message.
func (cc *CoreGrpcClient) InvokeJSON(ctx context.Context, method string, reqJSON []byte) ([]byte, error) {
	return invokeJSONConn(ctx, cc.conn, method, reqJSON)
}

// invokeJSONConn is the transport-agnostic transcoder seam used by InvokeJSON
// and exercised directly in tests with a fake connection.
func invokeJSONConn(ctx context.Context, conn grpc.ClientConnInterface, method string, reqJSON []byte) ([]byte, error) {
	md, err := resolveForgeMethod(method)
	if err != nil {
		return nil, err
	}

	in := dynamicpb.NewMessage(md.Input())
	if len(reqJSON) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(reqJSON, in); err != nil {
			return nil, fmt.Errorf("decode request for %q: %w", md.Name(), err)
		}
	}

	out := dynamicpb.NewMessage(md.Output())
	if err := conn.Invoke(ctx, coreFullMethod(method), in, out); err != nil {
		return nil, err
	}

	respJSON, err := protojson.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode response for %q: %w", md.Name(), err)
	}
	return respJSON, nil
}
