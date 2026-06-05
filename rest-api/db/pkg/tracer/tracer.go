// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"context"
	"reflect"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	// TracerKey is a key for current tracer
	TracerKey = "otel-go-contrib-tracer-labstack-echo"

	// TracerName is name of the tracer
	TracerName = "go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"

	// TraceHdr is header name for ngc trace id
	TraceHdr = "X-Ngc-Trace-Id"
)

// CurrentContextSpan is a thin wrapper around current context otel span
type CurrentContextSpan struct {
	Span oteltrace.Span
}

// End stop the span from leakage
func (c *CurrentContextSpan) End() {
	c.Span.End()
}

// TracerSpan holds span information
type TracerSpan struct {
}

func NewTracerSpan() *TracerSpan {
	return &TracerSpan{}
}

// LoadFromContext validate and get the spanner from current context
func (c *TracerSpan) LoadFromContext(ctx context.Context) (*CurrentContextSpan, bool) {
	// Assert we don't have a span on the context.
	span := oteltrace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return &CurrentContextSpan{
			Span: span,
		}, true
	}
	return nil, false
}

// SetAttribute set key value attribute to current span
func (c *TracerSpan) SetAttribute(cspan *CurrentContextSpan, key string, value interface{}) *CurrentContextSpan {
	if cspan == nil {
		return cspan
	}

	if value == "" {
		return cspan
	}

	svalue, ok := value.(string)
	if ok && cspan.Span.SpanContext().IsValid() {
		cspan.Span.SetAttributes(attribute.String(key, svalue))
	}

	return cspan
}

// CreateChildInCurrentContext create a child span from specified span name and context
func (c *TracerSpan) CreateChildInCurrentContext(ctx context.Context, spanName string) (context.Context, *CurrentContextSpan) {
	// Check if given context is empty
	var emptyCtx context.Context
	if reflect.DeepEqual(ctx, emptyCtx) {
		return ctx, nil
	}

	if spanName == "" {
		return ctx, nil
	}

	// get root tracer from context
	tracer, ok := ctx.Value(TracerKey).(oteltrace.Tracer)
	if !ok {
		return ctx, nil
	}

	// create a child span in current context
	newctx, span := tracer.Start(ctx, spanName)
	return newctx, &CurrentContextSpan{
		Span: span,
	}
}
