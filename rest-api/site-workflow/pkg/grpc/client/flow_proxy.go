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

// flowServiceName is the fully qualified Flow gRPC service. Its descriptors are
// registered in this binary because this package imports the generated flow
// bindings (see flow_client.go), so they can be resolved at runtime.
const flowServiceName = "v1.Flow"

// ErrUnknownFlowMethod is returned when a method name does not resolve to a
// unary RPC on the v1.Flow service.
var ErrUnknownFlowMethod = errors.New("unknown Flow method")

// flowMethodName returns the bare method name for a bare or fully qualified
// gRPC method ("/v1.Flow/CreateOperationRun" -> "CreateOperationRun").
func flowMethodName(method string) string {
	return path.Base(method)
}

// flowFullMethod returns the canonical "/v1.Flow/<Method>" gRPC path.
func flowFullMethod(method string) string {
	return "/" + flowServiceName + "/" + flowMethodName(method)
}

func resolveFlowMethod(method string) (protoreflect.MethodDescriptor, error) {
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(flowServiceName))
	if err != nil {
		return nil, fmt.Errorf("resolve service %q: %w", flowServiceName, err)
	}
	svc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is not a gRPC service", flowServiceName)
	}
	md := svc.Methods().ByName(protoreflect.Name(flowMethodName(method)))
	if md == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownFlowMethod, flowMethodName(method))
	}
	if md.IsStreamingClient() || md.IsStreamingServer() {
		return nil, fmt.Errorf("method %q is streaming and not supported by the proxy", md.Name())
	}
	return md, nil
}

// InvokeJSON proxies a unary v1.Flow call: it transcodes reqJSON (protojson)
// into the request message for method, invokes it on the Flow connection, and
// returns the protojson-encoded response. An empty reqJSON is treated as the
// zero-valued request message.
func (fg *FlowGrpcClient) InvokeJSON(ctx context.Context, method string, reqJSON []byte) ([]byte, error) {
	return invokeFlowJSONConn(ctx, fg.conn, method, reqJSON)
}

// invokeFlowJSONConn is the transport-agnostic transcoder seam used by
// InvokeJSON and exercised directly in tests with a fake connection.
func invokeFlowJSONConn(ctx context.Context, conn grpc.ClientConnInterface, method string, reqJSON []byte) ([]byte, error) {
	md, err := resolveFlowMethod(method)
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
	if err := conn.Invoke(ctx, flowFullMethod(method), in, out); err != nil {
		return nil, err
	}

	respJSON, err := protojson.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode response for %q: %w", md.Name(), err)
	}
	return respJSON, nil
}
