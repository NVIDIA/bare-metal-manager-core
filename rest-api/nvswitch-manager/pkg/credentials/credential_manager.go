// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/credential"

	log "github.com/sirupsen/logrus"
)

// ErrNotFound is returned when no credential is stored for a MAC. Callers use
// it to tell "this switch has no credential yet" apart from "the lookup
// failed", which matters because the two want different retry behavior.
var ErrNotFound = errors.New("credential not found")

// CredentialManager reads BMC and NVOS credentials for a switch, keyed by the
// switch's BMC MAC address.
//
// Read-only by design. NICo Core owns the lifecycle of switch credentials: it
// seeds them from the expected-switch record and rotates them from the switch
// controller, storing them envelope-encrypted in Postgres. NSM writing here
// too would race that rotation, so it only ever reads.
type CredentialManager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	// GetBMC returns the switch BMC's root credential, or ErrNotFound.
	GetBMC(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error)

	// GetNVOS returns the switch's NVOS admin credential, or ErrNotFound.
	GetNVOS(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error)
}

// New creates a new Credential Manager based on the given configuration.
func New(ctx context.Context, config *Config) (CredentialManager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.DataStoreType {
	case DatastoreTypeCore:
		log.Printf("Initializing CredentialManager with NICo Core datastore (config: %s)", config.CoreConfig)
		return config.CoreConfig.NewManager()
	case DatastoreTypeInMemory:
		log.Printf("Initializing CredentialManager with in-memory datastore")
		return NewInMemoryCredentialManager(), nil
	}

	return nil, fmt.Errorf("unsupported datastore type %s", config.DataStoreType)
}
