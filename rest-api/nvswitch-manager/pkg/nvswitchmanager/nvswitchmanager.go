// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nvswitchmanager

import (
	"context"
	"fmt"
	"net"

	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/credentials"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/nvswitchregistry"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/objects/nvswitch"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// NVSwitchManager coordinates registry and credential management for NV-Switch trays.
type NVSwitchManager struct {
	DataStoreType     DataStoreType
	Registry          nvswitchregistry.Registry
	CredentialManager credentials.CredentialManager
}

// New creates a new instance of NVSwitchManager.
func New(ctx context.Context, c Config) (*NVSwitchManager, error) {
	credentialManager, err := credentials.New(ctx, &c.CredentialConf)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize credential manager: %v", err)
	}

	var registry nvswitchregistry.Registry
	switch c.DSType {
	case DatastoreTypeInMemory:
		log.Printf("Initializing NV-Switch Manager with in-memory registry")
		registry = nvswitchregistry.NewInMemoryRegistry()
	case DatastoreTypePersistent:
		if c.DB == nil {
			return nil, fmt.Errorf("database connection required for persistent registry")
		}
		log.Printf("Initializing NV-Switch Manager with persistent (PostgreSQL) registry")
		registry = nvswitchregistry.NewPostgresRegistry(c.DB)
	default:
		return nil, fmt.Errorf("unsupported datastore type: %v", c.DSType)
	}

	return &NVSwitchManager{
		DataStoreType:     c.DSType,
		Registry:          registry,
		CredentialManager: credentialManager,
	}, nil
}

// Start initializes the manager.
func (nm *NVSwitchManager) Start(ctx context.Context) error {
	if err := nm.Registry.Start(ctx); err != nil {
		return err
	}
	return nm.CredentialManager.Start(ctx)
}

// Stop shuts down the manager.
func (nm *NVSwitchManager) Stop(ctx context.Context) error {
	if err := nm.Registry.Stop(ctx); err != nil {
		return err
	}
	return nm.CredentialManager.Stop(ctx)
}

// Register registers a new NV-Switch tray.
//
// In persistent mode, credentials carried on the tray are ignored: NICo Core
// owns switch credentials, seeding them from the expected-switch record and
// rotating them from the switch controller, so registration records identity
// and routing only. In in-memory mode there is no Core to read from, so the
// supplied credentials seed the in-memory store instead.
func (nm *NVSwitchManager) Register(ctx context.Context, tray *nvswitch.NVSwitchTray) (uuid.UUID, bool, error) {
	if tray.BMC == nil {
		return uuid.Nil, false, fmt.Errorf("tray BMC subsystem is required")
	}
	if tray.NVOS == nil {
		return uuid.Nil, false, fmt.Errorf("tray NVOS subsystem is required")
	}

	// Register first, then seed. Seeding beforehand would leave credentials
	// behind for a switch that never registered.
	id, created, err := nm.Registry.Register(ctx, tray)
	if err != nil {
		return id, created, err
	}

	// The registry has already accepted the switch at this point, so a seeding
	// failure reports the real id rather than uuid.Nil: the caller needs it to
	// reach the registered-but-unseeded switch and reconcile.
	if seeder, ok := nm.CredentialManager.(*credentials.InMemoryCredentialManager); ok {
		if tray.BMC.Credential != nil {
			if err := seeder.PutBMC(ctx, tray.BMC.MAC, tray.BMC.Credential); err != nil {
				return id, created, fmt.Errorf("failed to seed BMC credentials: %v", err)
			}
		}
		if tray.NVOS.Credential != nil {
			if err := seeder.PutNVOS(ctx, tray.BMC.MAC, tray.NVOS.Credential); err != nil {
				return id, created, fmt.Errorf("failed to seed NVOS credentials: %v", err)
			}
		}
	}

	return id, created, nil
}

// Get retrieves an NV-Switch by UUID and attaches credentials.
func (nm *NVSwitchManager) Get(ctx context.Context, id uuid.UUID) (*nvswitch.NVSwitchTray, error) {
	tray, err := nm.Registry.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if tray.BMC == nil {
		return nil, fmt.Errorf("switch %s has no BMC subsystem", id)
	}
	if tray.NVOS == nil {
		return nil, fmt.Errorf("switch %s has no NVOS subsystem", id)
	}

	bmcCred, err := nm.CredentialManager.GetBMC(ctx, tray.BMC.MAC)
	if err != nil {
		return nil, fmt.Errorf("loading BMC credentials for switch %s (MAC %s): %w", id, tray.BMC.MAC, err)
	}
	tray.BMC.Credential = bmcCred

	nvosCred, err := nm.CredentialManager.GetNVOS(ctx, tray.BMC.MAC)
	if err != nil {
		return nil, fmt.Errorf("loading NVOS credentials for switch %s (MAC %s): %w", id, tray.BMC.MAC, err)
	}
	tray.NVOS.Credential = nvosCred

	return tray, nil
}

// List returns all registered NV-Switches.
func (nm *NVSwitchManager) List(ctx context.Context) ([]*nvswitch.NVSwitchTray, error) {
	return nm.Registry.List(ctx)
}

// Delete removes an NV-Switch from the registry.
//
// Core-owned credentials are left alone: Core owns their lifecycle, and a
// switch deregistered here may still be a live, credentialed switch there.
// Credentials this manager seeded into its own in-memory store are dropped
// with the switch, so a later re-registration does not silently inherit them.
func (nm *NVSwitchManager) Delete(ctx context.Context, id uuid.UUID) error {
	// The MAC has to be read before the delete, but forgetting has to happen
	// after it succeeds: dropping the credentials first would strip a switch
	// that is still registered if the delete then fails.
	var seeder *credentials.InMemoryCredentialManager
	var bmcMAC net.HardwareAddr
	if manager, ok := nm.CredentialManager.(*credentials.InMemoryCredentialManager); ok {
		seeder = manager
		// Best effort: the registry delete below is what the caller asked for,
		// and a switch that cannot be loaded has no MAC to forget anyway.
		if tray, err := nm.Registry.Get(ctx, id); err == nil && tray.BMC != nil {
			bmcMAC = tray.BMC.MAC
		}
	}

	if err := nm.Registry.Delete(ctx, id); err != nil {
		return err
	}

	if seeder != nil && bmcMAC != nil {
		seeder.Forget(ctx, bmcMAC)
	}
	return nil
}
