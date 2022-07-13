/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
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
	// NetworkPolicyPriorityRuleIDMap maps networkPolicy priority to ruleID; where array index is
	// the priority, and value in each element is the last RuleID for that priority.
	NetworkPolicyPriorityRuleIDMap []uint16 `yaml:"networkPolicyPriorityRuleIDMap,omitempty"`
	// EnableNetworkPolicy is true if NetworkPolicies CRDs are applied.
	EnableNetworkPolicy bool `yaml:"enableNetworkPolicy,omitempty"`
}

// Config contains caller specified Controller configurations.
type Config struct {
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
	if c.Forge.DefaultASN == 0 {
		c.Forge.DefaultASN = 65535
	}
	if len(c.Forge.NetworkPolicyPriorityRuleIDMap) == 0 {
		c.Forge.NetworkPolicyPriorityRuleIDMap = vpc.NetworkPolicyPriorityRuleIDMapDefault
	}
	return c.validate()
}

func (c *Config) validate() error {
	// Validate
	if c.LeaderElection.LeaderElect && len(c.LeaderElection.ResourceName) == 0 {
		return fmt.Errorf("election is enabled without providing election resource")
	}
	if len(c.Forge.NetworkPolicyPriorityRuleIDMap) != len(vpc.NetworkPolicyPriorityRuleIDMapDefault) {
		return fmt.Errorf("incorrect network policy ruleid priority mapping, expected %d priorities, got %d priorities",
			len(vpc.NetworkPolicyPriorityRuleIDMapDefault), len(c.Forge.NetworkPolicyPriorityRuleIDMap))
	}
	lastRuleID := uint16(0)
	for _, ruleID := range c.Forge.NetworkPolicyPriorityRuleIDMap {
		if ruleID <= lastRuleID {
			return fmt.Errorf("incorrect network policy ruleid priority mapping out of order")
		}
		lastRuleID = ruleID
	}
	return nil
}
