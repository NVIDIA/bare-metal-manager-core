// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package otelecho provides OpenTelemetry instrumentation for the labstack/echo package.
//
// This package wraps the upstream OpenTelemetry contrib package
// (go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho)
// and adds custom functionality:
//   - Zerolog logging of trace IDs
//   - Setting X-Ngc-Trace-Id header
//   - Storing tracer in context for use by other packages
//
// The upstream package is used directly as a dependency instead of copying the code
// to avoid Apache license issues and to benefit from upstream updates and fixes.
//
// Note: The upstream package's go.mod contains a replace directive for the b3
// propagator, but this is resolved automatically by Go's module system when using
// the package as a dependency. The replace directive is ignored for dependencies
// and only affects builds within the upstream repository itself.
package otelecho
