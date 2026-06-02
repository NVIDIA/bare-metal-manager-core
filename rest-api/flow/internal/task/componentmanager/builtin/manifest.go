// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager"
	cmcatalog "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/catalog"
	computenico "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/compute/nico"
	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/mock"
	nvswitchnico "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/nvswitch/nico"
	nvswitchnsm "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/nvswitch/nvswitchmanager"
	powershelfnico "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/powershelf/nico"
	powershelfpsm "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/powershelf/psm"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico"
	nsmprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nvswitchmanager"
	psmprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/psm"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// This file is the Flow service component manager manifest. When adding a
// provider or component manager implementation compiled into the service, add
// its default mapping, decoder, descriptor, and runtime factory spec entries here.

// defaultServiceComponentManagers returns the component manager implementation
// map used when the Flow service is started without a component manager config
// file. A configured file is authoritative and does not merge with this map.
func defaultServiceComponentManagers() map[devicetypes.ComponentType]string {
	return map[devicetypes.ComponentType]string{
		devicetypes.ComponentTypeCompute:    computenico.ImplementationName,
		devicetypes.ComponentTypeNVSwitch:   nvswitchnico.ImplementationName,
		devicetypes.ComponentTypePowerShelf: powershelfnico.ImplementationName,
	}
}

// serviceProviderConfigDecoders returns all provider config decoders supported
// by the Flow service.
func serviceProviderConfigDecoders() []providerapi.ProviderConfigDecoder {
	return []providerapi.ProviderConfigDecoder{
		nicoprovider.ConfigDecoder{},
		psmprovider.ConfigDecoder{},
		nsmprovider.ConfigDecoder{},
	}
}

// serviceManagerConfigDecoders returns all manager config decoders supported
// by the Flow service.
func serviceManagerConfigDecoders() []cmconfig.ManagerConfigDecoder {
	return []cmconfig.ManagerConfigDecoder{
		computenico.ConfigDecoder{},
	}
}

// serviceDescriptors returns all component manager descriptors compiled into
// the Flow service. Descriptors stay in a separate manifest even though
// FactorySpec also contains a Descriptor because descriptor metadata is needed
// before runtime factories are built. Config validation and provider dependency
// discovery can use this static list without constructing config-dependent
// factory specs.
func serviceDescriptors() []cmcatalog.Descriptor {
	descriptors := []cmcatalog.Descriptor{
		computenico.Descriptor(),
		nvswitchnico.Descriptor(),
		nvswitchnsm.Descriptor(),
		powershelfnico.Descriptor(),
		powershelfpsm.Descriptor(),
	}

	descriptors = append(descriptors, mock.Descriptors()...)
	return descriptors
}

// serviceFactorySpecs returns all runtime component manager factory specs
// compiled into the Flow service. Factory specs pair descriptors with factories
// after service config has been decoded, so this manifest is intentionally
// separate from serviceDescriptors for managers whose factories need
// config-derived values.
func serviceFactorySpecs(
	config cmconfig.Config,
) ([]componentmanager.FactorySpec, error) {
	computePowerDelay, err := nicoComputePowerDelay(config)
	if err != nil {
		return nil, err
	}

	factorySpecs := []componentmanager.FactorySpec{
		computenico.FactorySpec(computePowerDelay),
		nvswitchnico.FactorySpec(),
		nvswitchnsm.FactorySpec(),
		powershelfnico.FactorySpec(),
		powershelfpsm.FactorySpec(),
	}

	factorySpecs = append(factorySpecs, mock.FactorySpecs()...)
	return factorySpecs, nil
}
