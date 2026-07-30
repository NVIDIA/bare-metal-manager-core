// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Hand-written gRPC stubs for DecommissionRack.
// TODO: regenerate from flow.proto via protoc.

package v1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	Flow_DecommissionRack_FullMethodName = "/v1.Flow/DecommissionRack"
)

// DecommissionRack is implemented on the flowClient to satisfy the FlowClient
// interface extension. It is added here so existing callers can use it without
// regenerating the full client from protoc.
func (c *flowClient) DecommissionRack(ctx context.Context, in *DecommissionRackRequest, opts ...grpc.CallOption) (*SubmitTaskResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SubmitTaskResponse)
	err := c.cc.Invoke(ctx, Flow_DecommissionRack_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnimplementedFlowServer_DecommissionRack provides the default
// "not implemented" response for DecommissionRack on the embedded
// UnimplementedFlowServer.
func (UnimplementedFlowServer) DecommissionRack(context.Context, *DecommissionRackRequest) (*SubmitTaskResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DecommissionRack not implemented")
}

// _Flow_DecommissionRack_Handler is the gRPC server handler for DecommissionRack.
func _Flow_DecommissionRack_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecommissionRackRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowServer).DecommissionRack(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Flow_DecommissionRack_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowServer).DecommissionRack(ctx, req.(*DecommissionRackRequest))
	}
	return interceptor(ctx, in, info, handler)
}
