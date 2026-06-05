// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package otelecho

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// TestFullIntegration tests the complete integration - verifies that
// the wrapper correctly stores the tracer in context so that util/tracer.go
// can use it to create child spans (simulating what util/tracer.go does)
func TestFullIntegration(t *testing.T) {
	provider := trace.NewNoopTracerProvider()
	otel.SetTextMapPropagator(propagation.TraceContext{})

	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Create a parent trace context
	ctx := context.Background()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		SpanID:  trace.SpanID{0x01},
	})
	ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
	ctx, _ = provider.Tracer(TracerName).Start(ctx, "parent")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))

	var tracerFound bool
	var headerSet bool
	var childSpanCreated bool

	router := echo.New()
	router.Use(Middleware("test-service", WithTracerProvider(provider)))
	router.GET("/test", func(c echo.Context) error {
		// Verify tracer is in context (this is what util/tracer.go needs)
		ctx := c.Request().Context()
		tracer, ok := ctx.Value(TracerKey).(trace.Tracer)
		if ok && tracer != nil {
			tracerFound = true

			// Simulate what util/tracer.go CreateChildInContext does
			childCtx, childSpan := tracer.Start(ctx, "child-span")
			if childCtx != nil && childSpan != nil {
				childSpanCreated = true
			}
		}

		// Verify header was set
		if c.Response().Header().Get(TraceHdr) != "" {
			headerSet = true
		}

		return c.NoContent(200)
	})

	router.ServeHTTP(w, r)

	response := w.Result()
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.True(t, tracerFound, "Tracer should be found in context for util/tracer.go")
	assert.True(t, headerSet, "X-Ngc-Trace-Id header should be set")
	assert.True(t, childSpanCreated, "Child span should be creatable using tracer from context")

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
}

// TestOriginalBehaviorMatch verifies that the wrapper behaves exactly like the original
// for all the original test cases
func TestOriginalBehaviorMatch(t *testing.T) {
	provider := trace.NewNoopTracerProvider()
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tests := []struct {
		name            string
		setupRequest    func() *http.Request
		expectedTraceID string
		expectHeader    bool
	}{
		{
			name: "with parent trace",
			setupRequest: func() *http.Request {
				r := httptest.NewRequest("GET", "/test", nil)
				ctx := context.Background()
				sc := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID: trace.TraceID{0xAA, 0xBB, 0xCC, 0xDD},
					SpanID:  trace.SpanID{0x01},
				})
				ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
				ctx, _ = provider.Tracer(TracerName).Start(ctx, "parent")
				otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))
				return r
			},
			expectedTraceID: "aabbccdd000000000000000000000000",
			expectHeader:    true,
		},
		{
			name: "without parent trace",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			expectedTraceID: "00000000000000000000000000000000", // Empty trace ID when no parent
			expectHeader:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.setupRequest()
			w := httptest.NewRecorder()

			var receivedTraceID string
			router := echo.New()
			router.Use(Middleware("test-service", WithTracerProvider(provider)))
			router.GET("/test", func(c echo.Context) error {
				span := trace.SpanFromContext(c.Request().Context())
				receivedTraceID = span.SpanContext().TraceID().String()
				headerValue := c.Response().Header().Get(TraceHdr)
				assert.Equal(t, receivedTraceID, headerValue, "Header should match trace ID")
				return c.NoContent(200)
			})

			router.ServeHTTP(w, r)
			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
			assert.Equal(t, tt.expectedTraceID, receivedTraceID, "Trace ID should match expected")
			if tt.expectHeader {
				headerValue := w.Result().Header.Get(TraceHdr)
				assert.NotEmpty(t, headerValue, "Header should be set")
			}
		})
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
}
