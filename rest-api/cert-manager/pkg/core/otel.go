// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// tracer is the OTel tracer to use for the core package
var tracer oteltrace.Tracer

func init() {
	tracer = otel.Tracer("nvmetal/cloud-cert-manager/pkg/core")
}

// StartOTELDaemon starts a go routine that waits on the provided context to quit and then shuts down the daemon
func StartOTELDaemon(ctx context.Context) {
	log := GetLogger(ctx)

	// Ignore this is most likely disabled
	log.Infof("Skipping OTEL startup - not supported")
}
