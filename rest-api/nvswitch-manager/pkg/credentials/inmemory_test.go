// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"net"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/credential"

	"github.com/stretchr/testify/assert"
)

func newCredential(user, password string) *credential.Credential {
	c := credential.New(user, password)
	return &c
}

func parseMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	assert.NoError(t, err, "failed to parse MAC %q", s)
	return m
}

func TestInMemoryStartStop(t *testing.T) {
	testCases := map[string]struct {
		setup func() *InMemoryCredentialManager
	}{
		"start and stop return nil": {
			setup: func() *InMemoryCredentialManager {
				return NewInMemoryCredentialManager()
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mgr := tc.setup()
			assert.NoError(t, mgr.Start(context.Background()))
			assert.NoError(t, mgr.Stop(context.Background()))
		})
	}
}

func TestInMemoryBMCPutGet(t *testing.T) {
	testCases := map[string]struct {
		initialPut   bool
		putMAC       string
		putCred      *credential.Credential
		putSameAgain bool // if true, immediately re-put a fresh-but-equal credential to exercise the idempotent skip path
		getMAC       string
		wantErr      bool
		wantUser     string
		wantPass     string
		samePtr      bool
	}{
		"get existing valid BMC credential": {
			initialPut: true,
			putMAC:     "00:11:22:33:44:55",
			putCred:    newCredential("admin", "secret"),
			getMAC:     "00:11:22:33:44:55",
			wantErr:    false,
			wantUser:   "admin",
			wantPass:   "secret",
			samePtr:    true,
		},
		"get existing invalid credential (empty user) returns not found": {
			initialPut: true,
			putMAC:     "00:11:22:33:44:66",
			putCred:    newCredential("", "nopass"),
			getMAC:     "00:11:22:33:44:66",
			wantErr:    true,
		},
		"get missing credential returns not found": {
			initialPut: false,
			getMAC:     "66:77:88:99:00:11",
			wantErr:    true,
		},
		"put same credential is no-op": {
			initialPut:   true,
			putMAC:       "aa:bb:cc:dd:ee:ff",
			putCred:      newCredential("user1", "p1"),
			putSameAgain: true,
			getMAC:       "aa:bb:cc:dd:ee:ff",
			wantErr:      false,
			wantUser:     "user1",
			wantPass:     "p1",
			samePtr:      true, // second put with equal-but-fresh pointer must be skipped, leaving original pointer in place
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewInMemoryCredentialManager()

			// Optional initial put
			if tc.initialPut {
				mac := parseMAC(t, tc.putMAC)
				assert.NoError(t, mgr.PutBMC(ctx, mac, tc.putCred))
				// Exercise the idempotent skip path with a fresh-but-equal
				// credential pointer. samePtr below verifies the original
				// pointer survived (i.e. the second Put was actually skipped,
				// not just rewritten with the same values).
				if tc.putSameAgain {
					assert.NoError(t, mgr.PutBMC(ctx, mac, newCredential(tc.putCred.User, tc.putCred.Password.Value)))
				}
			}

			// Get flow
			got, err := mgr.GetBMC(ctx, parseMAC(t, tc.getMAC))
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tc.wantUser, got.User)
			assert.Equal(t, tc.wantPass, got.Password.Value)

			if tc.samePtr && tc.initialPut {
				assert.Same(t, tc.putCred, got)
			}
		})
	}
}

func TestInMemoryPutDifferentCredentialOverwrites(t *testing.T) {
	ctx := context.Background()
	mgr := NewInMemoryCredentialManager()
	mac := parseMAC(t, "00:11:22:33:44:55")

	// Initial put succeeds
	assert.NoError(t, mgr.PutBMC(ctx, mac, newCredential("admin", "secret")))
	assert.NoError(t, mgr.PutNVOS(ctx, mac, newCredential("nvos", "nvos_secret")))

	// Put with different credentials overwrites (no error for in-memory)
	assert.NoError(t, mgr.PutBMC(ctx, mac, newCredential("admin", "different_pass")))
	assert.NoError(t, mgr.PutNVOS(ctx, mac, newCredential("nvos", "different_pass")))

	// Credentials are now the new values
	bmcCred, err := mgr.GetBMC(ctx, mac)
	assert.NoError(t, err)
	assert.Equal(t, "admin", bmcCred.User)
	assert.Equal(t, "different_pass", bmcCred.Password.Value)

	nvosCred, err := mgr.GetNVOS(ctx, mac)
	assert.NoError(t, err)
	assert.Equal(t, "nvos", nvosCred.User)
	assert.Equal(t, "different_pass", nvosCred.Password.Value)
}

func TestInMemoryNVOSPutGet(t *testing.T) {
	testCases := map[string]struct {
		initialPut bool
		putMAC     string
		putCred    *credential.Credential
		getMAC     string
		wantErr    bool
		wantUser   string
		wantPass   string
	}{
		"get existing valid NVOS credential": {
			initialPut: true,
			putMAC:     "00:11:22:33:44:55",
			putCred:    newCredential("nvos_admin", "nvos_secret"),
			getMAC:     "00:11:22:33:44:55",
			wantErr:    false,
			wantUser:   "nvos_admin",
			wantPass:   "nvos_secret",
		},
		"get missing NVOS credential returns not found": {
			initialPut: false,
			getMAC:     "66:77:88:99:00:11",
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewInMemoryCredentialManager()

			// Optional initial put
			if tc.initialPut {
				mac := parseMAC(t, tc.putMAC)
				assert.NoError(t, mgr.PutNVOS(ctx, mac, tc.putCred))
			}

			// Get flow
			got, err := mgr.GetNVOS(ctx, parseMAC(t, tc.getMAC))
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tc.wantUser, got.User)
			assert.Equal(t, tc.wantPass, got.Password.Value)
		})
	}
}
