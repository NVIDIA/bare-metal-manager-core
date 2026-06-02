// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
)

// TemporalConfig holds configuration for Temporal communication
type MetricsConfig struct {
	Enabled bool
	Port    int
}

// GetListenAddr returns the local address for listen socket.
func (mcfg *MetricsConfig) GetListenAddr() string {
	return fmt.Sprintf(":%v", mcfg.Port)
}

// NewMetricsConfig initializes and returns a configuration object for managing Metrics
func NewMetricsConfig(enabled bool, port int) *MetricsConfig {
	return &MetricsConfig{
		Enabled: enabled,
		Port:    port,
	}
}
