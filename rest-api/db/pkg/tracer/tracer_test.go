// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
)

func Test_LoadFromContext(t *testing.T) {
	type args struct {
		ctx             context.Context
		expectValidSpan bool
		expectSpan      *CurrentContextSpan
	}

	// OTEL Spanner configuration
	provider := trace.NewNoopTracerProvider()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})

	ctx := trace.ContextWithRemoteSpanContext(context.Background(), sc)
	tracer := provider.Tracer("Test_LoadFromContext")
	validspanctx, validspan := tracer.Start(ctx, "Test_LoadFromContext")

	tracerSpan := NewTracerSpan()

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test load span success in case span information not present in context",
			args: args{
				ctx:             context.Background(),
				expectValidSpan: false,
				expectSpan:      nil,
			},
		},
		{
			name: "test load span success in case span information present in context",
			args: args{
				ctx:             validspanctx,
				expectValidSpan: true,
				expectSpan: &CurrentContextSpan{
					validspan,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, valid := tracerSpan.LoadFromContext(tt.args.ctx)
			assert.Equal(t, valid, tt.args.expectValidSpan)
			assert.Equal(t, span, tt.args.expectSpan)
		})
	}
}

func Test_SetSpanAttribute(t *testing.T) {
	type args struct {
		inputAttributeKey   string
		inputAttributeValue string
		inputSpan           *CurrentContextSpan
		expectSpan          *CurrentContextSpan
	}

	// OTEL Spanner configuration
	provider := trace.NewNoopTracerProvider()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})

	ctx := trace.ContextWithRemoteSpanContext(context.Background(), sc)
	tracer := provider.Tracer("Test_SetSpanAttribute")
	_, validspan := tracer.Start(ctx, "Test_SetSpanAttribute")

	tracerSpan := NewTracerSpan()

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test set span attribute success returns valid span",
			args: args{
				inputAttributeKey:   "test",
				inputAttributeValue: "test",
				inputSpan: &CurrentContextSpan{
					Span: validspan,
				},
				expectSpan: &CurrentContextSpan{
					Span: validspan,
				},
			},
		},
		{
			name: "test set span attribute success returns nil span",
			args: args{
				inputAttributeKey:   "test",
				inputAttributeValue: "test",
				inputSpan:           nil,
				expectSpan:          nil,
			},
		},
		{
			name: "test set span attribute success returns nil in case value empty",
			args: args{
				inputAttributeKey:   "test",
				inputAttributeValue: "",
				inputSpan: &CurrentContextSpan{
					Span: validspan,
				},
				expectSpan: &CurrentContextSpan{
					Span: validspan,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := tracerSpan.SetAttribute(tt.args.inputSpan, tt.args.inputAttributeKey, tt.args.inputAttributeValue)
			assert.Equal(t, span, tt.args.expectSpan)
		})
	}
}

func Test_CreateChildInCurrentContext(t *testing.T) {
	type args struct {
		inputSpanName string
		inputCtx      context.Context
		expectSpan    *CurrentContextSpan
	}

	// OTEL Spanner configuration
	provider := trace.NewNoopTracerProvider()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})

	ctx1 := trace.ContextWithRemoteSpanContext(context.Background(), sc)
	tracer := provider.Tracer("Test_CreateChildInCurrentContext")
	_, validspan := tracer.Start(ctx1, "Test_CreateChildInCurrentContext")

	ctx2 := ctx1

	// Set parent tracer in current context
	ctx1 = context.WithValue(ctx1, TracerKey, tracer)
	tracerSpan := NewTracerSpan()

	var ctx3 context.Context

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test child span creation in context failure, no tracerKey presents",
			args: args{
				inputCtx:      ctx2,
				inputSpanName: "test",
				expectSpan:    nil,
			},
		},
		{
			name: "test child span creation in context failure, empty span name",
			args: args{
				inputCtx:      ctx2,
				inputSpanName: "",
				expectSpan:    nil,
			},
		},
		{
			name: "test child span creation in context failure, empty context",
			args: args{
				inputCtx:      ctx3,
				inputSpanName: "",
				expectSpan:    nil,
			},
		},
		{
			name: "test child span creation success",
			args: args{
				inputCtx:      ctx1,
				inputSpanName: "test",
				expectSpan: &CurrentContextSpan{
					Span: validspan,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, span := tracerSpan.CreateChildInCurrentContext(tt.args.inputCtx, tt.args.inputSpanName)
			assert.Equal(t, span, tt.args.expectSpan)
		})
	}
}
