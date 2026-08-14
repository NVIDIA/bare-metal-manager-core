// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nvswitchmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/credential"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/credentials"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/nvswitchregistry"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/objects/bmc"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/objects/nvos"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/pkg/objects/nvswitch"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager() *NVSwitchManager {
	return &NVSwitchManager{
		Registry:          nvswitchregistry.NewInMemoryRegistry(),
		CredentialManager: credentials.NewInMemoryCredentialManager(),
	}
}

// seeder exposes the in-memory store's write methods, which the read-only
// CredentialManager interface does not carry. Registration no longer stores
// credentials in persistent mode, so tests seed them the same way local dev
// does.
func seeder(t *testing.T, nm *NVSwitchManager) *credentials.InMemoryCredentialManager {
	t.Helper()
	m, ok := nm.CredentialManager.(*credentials.InMemoryCredentialManager)
	require.True(t, ok, "test manager must use the in-memory credential manager")
	return m
}

func mustParseBMC(t *testing.T, mac, ip string) *bmc.BMC {
	t.Helper()
	b, err := bmc.New(mac, ip, nil)
	require.NoError(t, err)
	return b
}

func mustParseNVOS(t *testing.T, mac, ip string) *nvos.NVOS {
	t.Helper()
	n, err := nvos.New(mac, ip, nil)
	require.NoError(t, err)
	return n
}

func newTestTray(t *testing.T) *nvswitch.NVSwitchTray {
	t.Helper()
	return &nvswitch.NVSwitchTray{
		UUID: uuid.New(),
		BMC:  mustParseBMC(t, "AA:BB:CC:DD:EE:FF", "10.0.0.1"),
		NVOS: mustParseNVOS(t, "11:22:33:44:55:66", "10.0.0.2"),
	}
}

func TestNVSwitchManager_Register(t *testing.T) {
	testCases := map[string]struct {
		tray        func(t *testing.T) *nvswitch.NVSwitchTray
		wantErr     bool
		errContains string
	}{
		"register with BMC and NVOS succeeds": {
			tray:    newTestTray,
			wantErr: false,
		},
		"register without BMC returns error": {
			tray: func(t *testing.T) *nvswitch.NVSwitchTray {
				tray := newTestTray(t)
				tray.BMC = nil
				return tray
			},
			wantErr:     true,
			errContains: "BMC subsystem is required",
		},
		"register without NVOS returns error": {
			tray: func(t *testing.T) *nvswitch.NVSwitchTray {
				tray := newTestTray(t)
				tray.NVOS = nil
				return tray
			},
			wantErr:     true,
			errContains: "NVOS subsystem is required",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			nm := newTestManager()
			ctx := context.Background()

			_, _, err := nm.Register(ctx, tc.tray(t))
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNVSwitchManager_Get(t *testing.T) {
	testCases := map[string]struct {
		setupBMCCred  bool
		setupNVOSCred bool
		wantErr       bool
		errContains   string
	}{
		"get with BMC and NVOS credentials succeeds": {
			setupBMCCred:  true,
			setupNVOSCred: true,
			wantErr:       false,
		},
		"get without BMC credentials returns error": {
			setupBMCCred:  false,
			setupNVOSCred: false,
			wantErr:       true,
			errContains:   "loading BMC credentials",
		},
		"get with BMC credentials but missing NVOS credentials returns error": {
			setupBMCCred:  true,
			setupNVOSCred: false,
			wantErr:       true,
			errContains:   "loading NVOS credentials",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			nm := newTestManager()
			ctx := context.Background()

			tray := newTestTray(t)

			if tc.setupBMCCred {
				c := credential.New("admin", "pass")
				require.NoError(t, seeder(t, nm).PutBMC(ctx, tray.BMC.MAC, &c))
			}
			if tc.setupNVOSCred {
				c := credential.New("nvos_admin", "nvos_pass")
				require.NoError(t, seeder(t, nm).PutNVOS(ctx, tray.BMC.MAC, &c))
			}

			_, _, err := nm.Registry.Register(ctx, tray)
			require.NoError(t, err)

			got, err := nm.Get(ctx, tray.UUID)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			assert.NotNil(t, got.BMC.Credential, "BMC credential should be attached")
			assert.Equal(t, "admin", got.BMC.Credential.User)

			assert.NotNil(t, got.NVOS.Credential, "NVOS credential should be attached")
			assert.Equal(t, "nvos_admin", got.NVOS.Credential.User)
		})
	}
}

func TestNVSwitchManager_Get_NotFound(t *testing.T) {
	nm := newTestManager()
	ctx := context.Background()

	got, err := nm.Get(ctx, uuid.New())
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestNVSwitchManager_Get_NilBMC(t *testing.T) {
	nm := newTestManager()
	ctx := context.Background()

	tray := newTestTray(t)
	_, _, err := nm.Registry.Register(ctx, tray)
	require.NoError(t, err)

	// Nil out BMC after registration to simulate corrupt/incomplete data.
	tray.BMC = nil

	got, err := nm.Get(ctx, tray.UUID)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "no BMC subsystem")
}

func TestNVSwitchManager_Get_NilNVOS(t *testing.T) {
	nm := newTestManager()
	ctx := context.Background()

	tray := newTestTray(t)
	_, _, err := nm.Registry.Register(ctx, tray)
	require.NoError(t, err)

	// Nil out NVOS after registration to simulate corrupt/incomplete data.
	tray.NVOS = nil

	got, err := nm.Get(ctx, tray.UUID)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "no NVOS subsystem")
}

// Delete must drop credentials this manager seeded itself, so a switch
// re-registered on the same MAC does not silently inherit the old ones.
// Core-owned credentials are a different matter and are never touched here.
func TestNVSwitchManager_Delete_ForgetsSeededCredentials(t *testing.T) {
	nm := newTestManager()
	ctx := context.Background()

	tray := newTestTray(t)
	bmcCred := credential.New("admin", "pass")
	tray.BMC.Credential = &bmcCred
	nvosCred := credential.New("nvos_admin", "nvos_pass")
	tray.NVOS.Credential = &nvosCred

	id, _, err := nm.Register(ctx, tray)
	require.NoError(t, err)

	// Seeded by Register, so readable before the delete.
	_, err = nm.CredentialManager.GetBMC(ctx, tray.BMC.MAC)
	require.NoError(t, err)

	require.NoError(t, nm.Delete(ctx, id))

	_, err = nm.CredentialManager.GetBMC(ctx, tray.BMC.MAC)
	assert.ErrorIs(t, err, credentials.ErrNotFound)
	_, err = nm.CredentialManager.GetNVOS(ctx, tray.BMC.MAC)
	assert.ErrorIs(t, err, credentials.ErrNotFound)
}

// A failed registration must not leave credentials behind for a switch that
// does not exist, which is why Register seeds only after the registry accepts.
// Two ways in: validation rejects the tray before the registry is reached, and
// the registry itself rejects it. Neither may seed.
func TestNVSwitchManager_Register_NoSeedWhenValidationRejects(t *testing.T) {
	nm := newTestManager()
	ctx := context.Background()

	tray := newTestTray(t)
	bmcCred := credential.New("admin", "pass")
	tray.BMC.Credential = &bmcCred
	tray.NVOS = nil // rejected before the registry is reached

	_, _, err := nm.Register(ctx, tray)
	require.Error(t, err)

	_, err = nm.CredentialManager.GetBMC(ctx, tray.BMC.MAC)
	assert.ErrorIs(t, err, credentials.ErrNotFound)
}

// rejectingRegistry fails every Register, leaving the rest of the Registry
// behaviour to the in-memory implementation it embeds.
type rejectingRegistry struct {
	nvswitchregistry.Registry
	err error
}

func (r *rejectingRegistry) Register(context.Context, *nvswitch.NVSwitchTray) (uuid.UUID, bool, error) {
	return uuid.Nil, false, r.err
}

func TestNVSwitchManager_Register_NoSeedWhenRegistryRejects(t *testing.T) {
	ctx := context.Background()
	rejected := errors.New("registry rejected the switch")
	nm := &NVSwitchManager{
		Registry: &rejectingRegistry{
			Registry: nvswitchregistry.NewInMemoryRegistry(),
			err:      rejected,
		},
		CredentialManager: credentials.NewInMemoryCredentialManager(),
	}

	// A fully valid tray, so the registry is what does the rejecting.
	tray := newTestTray(t)
	bmcCred := credential.New("admin", "pass")
	tray.BMC.Credential = &bmcCred
	nvosCred := credential.New("nvos-admin", "nvos-pass")
	tray.NVOS.Credential = &nvosCred

	_, _, err := nm.Register(ctx, tray)
	require.ErrorIs(t, err, rejected)

	_, err = nm.CredentialManager.GetBMC(ctx, tray.BMC.MAC)
	assert.ErrorIs(t, err, credentials.ErrNotFound)
	_, err = nm.CredentialManager.GetNVOS(ctx, tray.BMC.MAC)
	assert.ErrorIs(t, err, credentials.ErrNotFound)
}
