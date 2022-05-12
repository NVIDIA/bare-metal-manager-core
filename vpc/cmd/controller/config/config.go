/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// HealthConfig contains health probing configuration.
type HealthConfig struct {
	HealthProbeBindAddress string `yaml:"healthProbeBindAddress,omitempty"`
}

// MetricConfig contains metric configuration.
type MetricConfig struct {
	BindAddress string `yaml:"bindAddress,omitempty"`
}

// WebhookConfig contains webhook server configuration.
type WebhookConfig struct {
	Port int `yaml:"port,omitempty"`
}

// LeaderElectionConfig contains webhook configuration.
type LeaderElectionConfig struct {
	LeaderElect  bool   `yaml:"leaderElect,omitempty"`
	ResourceName string `yaml:"resourceName,omitempty"`
}

// ForgeConfig contains VPC configuration.
type ForgeConfig struct {
	// HBNDevice is true if managed leaf devices are HBN on DPUs.
	HBNDevice bool `yaml:"hbnDevice,omitempty"`
	// DefaultASN is default ASN assigned to leaf devices.
	DefaultASN uint32 `yaml:"defaultASN,omitempty"`
}

// Config contains caller specified Controller configurations.
type Config struct {
	Namespace      string               `yaml:"namespace,omitempty"`
	Health         HealthConfig         `yaml:"health,omitempty"`
	Metrics        MetricConfig         `yaml:"metrics,omitempty"`
	Webhook        WebhookConfig        `yaml:"webhook,omitempty"`
	LeaderElection LeaderElectionConfig `yaml:"leaderElection,omitempty"`
	Forge          ForgeConfig          `yaml:"forge,omitempty"`
}

func (c *Config) Parse(in []byte) error {
	if err := yaml.Unmarshal(in, c); err != nil {
		return err
	}
	// Validate
	if c.LeaderElection.LeaderElect && len(c.LeaderElection.ResourceName) == 0 {
		return fmt.Errorf("election is enabled without providing election resource")
	}
	logf.Log.V(1).Info("Configure before defaulting", "Config", c)
	// Defaulting
	if len(c.Health.HealthProbeBindAddress) == 0 {
		c.Health.HealthProbeBindAddress = ":8081"
	}
	if len(c.Metrics.BindAddress) == 0 {
		c.Metrics.BindAddress = "127.0.0.1:8080"
	}
	if c.Webhook.Port == 0 {
		c.Webhook.Port = 9443
	}
	if len(c.Namespace) == 0 {
		c.Namespace = "forge-system"
	}
	if c.Forge.DefaultASN == 0 {
		c.Forge.DefaultASN = 65535
	}
	return nil
}
