// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/credential"
	log "github.com/sirupsen/logrus"
)

const (
	bmcPrefix  = "bmc:"
	nvosPrefix = "nvos:"
)

// InMemoryCredentialManager implements the CredentialManager interface with an
// in-memory store, for local development and tests. Nothing in the service
// writes credentials any more, so callers seed it directly with PutBMC/PutNVOS
// — those are deliberately not part of the CredentialManager interface.
type InMemoryCredentialManager struct {
	store map[string]*credential.Credential
	mu    sync.RWMutex
}

func NewInMemoryCredentialManager() *InMemoryCredentialManager {
	return &InMemoryCredentialManager{
		store: make(map[string]*credential.Credential),
	}
}

// Start InMemoryCredentialManager (NO-OP)
func (m *InMemoryCredentialManager) Start(ctx context.Context) error {
	log.Printf("Starting InMem credential manager")
	// No initialization needed for in-memory store
	return nil
}

// Stop InMemoryCredentialManager (NO-OP)
func (m *InMemoryCredentialManager) Stop(ctx context.Context) error {
	log.Printf("Stopping InMem credential manager")
	// No cleanup needed for in-memory store
	return nil
}

func (m *InMemoryCredentialManager) bmcKey(mac net.HardwareAddr) string {
	return bmcPrefix + mac.String()
}

func (m *InMemoryCredentialManager) nvosKey(mac net.HardwareAddr) string {
	return nvosPrefix + mac.String()
}

func (m *InMemoryCredentialManager) get(kind, key string, mac net.HardwareAddr) (*credential.Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cred, exists := m.store[key]
	if !exists {
		return nil, fmt.Errorf("%s credential for %s: %w", kind, mac, ErrNotFound)
	}

	if !cred.IsValid() {
		return nil, fmt.Errorf("%s credential for %s is not valid", kind, mac)
	}

	return cred, nil
}

func (m *InMemoryCredentialManager) put(kind, key string, mac net.HardwareAddr, cred *credential.Credential) error {
	if cred == nil {
		return fmt.Errorf("%s credential for %s is nil", kind, mac)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, exists := m.store[key]; exists {
		if existing.Equal(cred) {
			log.Infof("%s credentials for %s already exist and match; skipping write", kind, mac)
			return nil
		}
		log.Warnf("%s credentials for %s differ from existing; overwriting in-memory entry", kind, mac)
	}

	m.store[key] = cred
	return nil
}

// GetBMC returns the BMC credential for mac, or ErrNotFound.
func (m *InMemoryCredentialManager) GetBMC(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error) {
	return m.get("BMC", m.bmcKey(mac), mac)
}

// PutBMC seeds the BMC credential for mac, replacing any current value.
func (m *InMemoryCredentialManager) PutBMC(ctx context.Context, mac net.HardwareAddr, cred *credential.Credential) error {
	return m.put("BMC", m.bmcKey(mac), mac, cred)
}

// GetNVOS returns the NVOS credential for mac, or ErrNotFound.
func (m *InMemoryCredentialManager) GetNVOS(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error) {
	return m.get("NVOS", m.nvosKey(mac), mac)
}

// PutNVOS seeds the NVOS credential for mac, replacing any current value.
func (m *InMemoryCredentialManager) PutNVOS(ctx context.Context, mac net.HardwareAddr, cred *credential.Credential) error {
	return m.put("NVOS", m.nvosKey(mac), mac, cred)
}

// Forget drops both seeded credentials for mac. No-op if absent, so callers
// can use it to clean up without first checking what was seeded.
func (m *InMemoryCredentialManager) Forget(ctx context.Context, mac net.HardwareAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.store, m.bmcKey(mac))
	delete(m.store, m.nvosKey(mac))
}
