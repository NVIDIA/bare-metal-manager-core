// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package flowgrpc

import (
	"fmt"
	"time"

	computils "github.com/NVIDIA/infra-controller-rest/site-agent/pkg/components/utils"
	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricFlowStatus is the metric name for the Flow gRPC health status
	MetricFlowStatus = "flow_grpc_health_status"
)

// Init initializes the Flow gRPC client manager
func (flowgrpc *API) Init() {
	// Check if Flow is enabled via environment variable
	if !ManagerAccess.Conf.EB.FlowGrpc.Enabled {
		ManagerAccess.Data.EB.Log.Info().Msg("Flow: Flow gRPC is disabled, skipping initialization")
		return
	}

	ManagerAccess.Data.EB.Log.Info().Msg("Flow: Initializing Flow gRPC client manager")

	prometheus.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "elektra_site_agent",
			Name:      MetricFlowStatus,
			Help:      "Flow gRPC health status",
		},
			func() float64 {
				return float64(ManagerAccess.Data.EB.Managers.FlowGrpc.State.HealthStatus.Load())
			}))

	ManagerAccess.Data.EB.Managers.FlowGrpc.State.HealthStatus.Store(uint64(computils.CompNotKnown))

	// initialize workflow metrics
	ManagerAccess.Data.EB.Managers.FlowGrpc.State.WflowMetrics = newWorkflowMetrics()
}

// Start starts the Flow gRPC client manager
func (flowgrpc *API) Start() {
	ManagerAccess.Data.EB.Log.Info().Msg("Flow gRPC: Starting Flow gRPC client manager")

	// Check if Flow is enabled via environment variable
	if !ManagerAccess.Conf.EB.FlowGrpc.Enabled {
		ManagerAccess.Data.EB.Log.Info().Msg("Flow gRPC: Flow gRPC is disabled, skipping initialization")
		return
	}

	// Site Agent should not be able to start if the Flow gRPC is enabled but the client cannot be created
	start := time.Now()
	backoff := client.FlowGrpcConnectionBackoffInitial
	for {
		err := flowgrpc.CreateGrpcClient()
		if err == nil {
			ManagerAccess.Data.EB.Log.Info().Msg("Flow gRPC: successfully created gRPC client")
			break
		}
		if time.Since(start) >= client.FlowGrpcConnectionRetryTimeout {
			panic(fmt.Errorf("Flow gRPC: failed to create gRPC client within %s: %w", client.FlowGrpcConnectionRetryTimeout, err))
		}
		ManagerAccess.Data.EB.Log.Error().Err(err).Dur("RetryIn", backoff).Msg("Flow gRPC: failed to create gRPC client, retrying")
		time.Sleep(backoff)
		backoff *= 2
		if backoff > client.FlowGrpcConnectionBackoffMax {
			backoff = client.FlowGrpcConnectionBackoffMax
		}
	}
}

// GetState returns the current state of the Flow gRPC client manager
func (flowgrpc *API) GetState() []string {
	state := ManagerAccess.Data.EB.Managers.FlowGrpc.State
	var strs []string
	strs = append(strs, fmt.Sprintln(" GRPC Succeeded:", state.GrpcSucc.Load()))
	strs = append(strs, fmt.Sprintln(" GRPC Failed:", state.GrpcFail.Load()))
	strs = append(strs, fmt.Sprintln(" GRPC Status:", computils.CompStatus(state.HealthStatus.Load())))
	strs = append(strs, fmt.Sprintln(" GRPC Last Error:", state.Err))

	return strs
}

// GetGrpcClientVersion returns the current version of the Flow gRPC client
func (flowgrpc *API) GetGrpcClientVersion() int64 {
	return ManagerAccess.Data.EB.Managers.FlowGrpc.Client.Version()
}
