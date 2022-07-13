/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

// ConfigurationRequest defines interface to configure a network device.
type ConfigurationRequest interface {
	Equal(ConfigurationRequest) bool
	Key() string
	GetBackendState(*vpcManager) (ConfigurationBackendState, error)
	SetBackendState(*vpcManager, ConfigurationBackendState, error, bool) error
}
