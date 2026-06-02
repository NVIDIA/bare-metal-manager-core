// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package coregrpc

import (
	"time"

	coregrpctypes "github.com/NVIDIA/infra-controller-rest/site-agent/pkg/datatypes/managertypes/coregrpc"
	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace         = "elektra_site_agent"
	metricCarbideGrpcLatency = "carbide_grpc_client_latency_seconds"
	metricWorkflowLatency    = "workflow_latency_seconds"
)

type grpcClientMetrics struct {
	responseLatency *prometheus.HistogramVec
}

func makeGrpcClientMetrics() client.Metrics {
	metrics := &grpcClientMetrics{
		responseLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Name:      metricCarbideGrpcLatency,
				Help:      "Response latency of each RPC",
				Buckets:   []float64{0.0005, 0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0},
			},
			[]string{"grpc_method", "grpc_status_code"}),
	}
	prometheus.MustRegister(metrics.responseLatency)
	return metrics
}

func (m *grpcClientMetrics) RecordRpcResponse(method, code string, duration time.Duration) {
	ManagerAccess.Data.EB.Log.Debug().Msgf("method=%s, code=%s, duration=%v", method, code, duration)
	m.responseLatency.WithLabelValues(method, code).Observe(duration.Seconds())
}

type wflowMetrics struct {
	latency *prometheus.HistogramVec
}

func newWorkflowMetrics() coregrpctypes.WorkflowMetrics {
	metrics := &wflowMetrics{
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Name:      metricWorkflowLatency,
				Help:      "Latency of each workflow",
				Buckets:   []float64{0.0005, 0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0},
			},
			[]string{"activity", "status"}),
	}
	prometheus.MustRegister(metrics.latency)
	return metrics
}

func (m *wflowMetrics) RecordLatency(activity string, status coregrpctypes.WorkflowStatus, duration time.Duration) {
	ManagerAccess.Data.EB.Log.Debug().Msgf("activity=%s, status=%s, duration=%v", activity, status, duration)
	m.latency.WithLabelValues(activity, string(status)).Observe(duration.Seconds())
}
