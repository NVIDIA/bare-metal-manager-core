// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

// Metrics interface that defines call-back functions for RPC metrics
type Metrics interface {
	// RecordRpcResponse call-back method that includes rpc method, response code, and duration
	RecordRpcResponse(method, code string, duration time.Duration)
}

func newGrpcUnaryMetricsInterceptor(metrics Metrics) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req interface{}, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var code codes.Code

		defer func(startTime time.Time) {
			metrics.RecordRpcResponse(method, normalizeRPCCode(code), time.Since(startTime))
		}(time.Now())

		err := invoker(ctx, method, req, reply, cc, opts...)
		code = status.Code(err)
		return err
	}
}

func newGrpcStreamMetricsInterceptor(metrics Metrics) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		var code codes.Code

		defer func(startTime time.Time) {
			metrics.RecordRpcResponse(method, normalizeRPCCode(code), time.Since(startTime))
		}(time.Now())

		s, err := streamer(ctx, desc, cc, method, opts...)
		code = status.Code(err)
		return s, err
	}
}

// to match nico gRPC status code, which is translated as Ok, instead of go translation of OK
func normalizeRPCCode(code codes.Code) string {
	if code == codes.OK {
		return "Ok"
	}
	return code.String()
}
