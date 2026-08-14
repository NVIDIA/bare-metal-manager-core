// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeForge serves just the two credential RPCs NSM calls; every other method
// falls through to the generated Unimplemented stub.
type fakeForge struct {
	corev1.UnimplementedForgeServer

	bmcResp  *corev1.GetBmcCredentialsResponse
	bmcErr   error
	nvosResp *corev1.GetBmcCredentialsResponse
	nvosErr  error

	// gotNvosMac records the MAC the server actually received, so the test can
	// confirm the client sends the bmc_mac_addr selector rather than a switch id.
	gotNvosMac string
	gotBmcMac  string
}

func (f *fakeForge) GetSwitchBmcCredentials(
	_ context.Context,
	req *corev1.GetSwitchBmcCredentialsRequest,
) (*corev1.GetBmcCredentialsResponse, error) {
	f.gotBmcMac = req.GetBmcMacAddr()
	return f.bmcResp, f.bmcErr
}

func (f *fakeForge) GetSwitchNvosCredentials(
	_ context.Context,
	req *corev1.GetSwitchNvosCredentialsRequest,
) (*corev1.GetBmcCredentialsResponse, error) {
	f.gotNvosMac = req.GetBmcMacAddr()
	return f.nvosResp, f.nvosErr
}

// newTestCoreManager wires a CoreCredentialManager to an in-process Core over
// bufconn. TLS is skipped here on purpose: NewManager's mTLS setup needs real
// SPIFFE certs on disk, and what these tests exercise is the request/response
// mapping, not the transport.
func newTestCoreManager(t *testing.T, srv *fakeForge) *CoreCredentialManager {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	corev1.RegisterForgeServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &CoreCredentialManager{
		client:  corev1.NewForgeClient(conn),
		conn:    conn,
		timeout: 5 * time.Second,
	}
}

func usernamePasswordResponse(user, pass string) *corev1.GetBmcCredentialsResponse {
	return &corev1.GetBmcCredentialsResponse{
		Credentials: &corev1.BmcCredentials{
			Type: &corev1.BmcCredentials_UsernamePassword{
				UsernamePassword: &corev1.UsernamePassword{Username: user, Password: pass},
			},
		},
	}
}

func TestCoreGetNVOS(t *testing.T) {
	mac := parseMAC(t, "00:11:22:33:44:55")

	testCases := map[string]struct {
		resp         *corev1.GetBmcCredentialsResponse
		err          error
		wantUser     string
		wantPass     string
		wantErr      bool
		wantNotFound bool
		errContains  string
	}{
		"credential is returned": {
			resp:     usernamePasswordResponse("nvos_admin", "nvos_pass"),
			wantUser: "nvos_admin",
			wantPass: "nvos_pass",
		},
		"not found maps to ErrNotFound": {
			err:          status.Error(codes.NotFound, "switch_nvos_credentials"),
			wantErr:      true,
			wantNotFound: true,
		},
		"transport error is not ErrNotFound": {
			err:         status.Error(codes.Unavailable, "core is down"),
			wantErr:     true,
			errContains: "core is down",
		},
		"permission denied is not ErrNotFound": {
			err:         status.Error(codes.PermissionDenied, "rbac"),
			wantErr:     true,
			errContains: "rbac",
		},
		"session token instead of password is rejected": {
			resp: &corev1.GetBmcCredentialsResponse{
				Credentials: &corev1.BmcCredentials{
					Type: &corev1.BmcCredentials_SessionToken{
						SessionToken: &corev1.SessionToken{Token: "t"},
					},
				},
			},
			wantErr:     true,
			errContains: "no username/password",
		},
		"empty username is rejected": {
			resp:        usernamePasswordResponse("", "p"),
			wantErr:     true,
			errContains: "invalid",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			srv := &fakeForge{nvosResp: tc.resp, nvosErr: tc.err}
			mgr := newTestCoreManager(t, srv)

			got, err := mgr.GetNVOS(context.Background(), mac)

			assert.Equal(t, mac.String(), srv.gotNvosMac, "client must select by BMC MAC")

			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
				assert.Equal(t, tc.wantNotFound, errors.Is(err, ErrNotFound))
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.wantUser, got.User)
			assert.Equal(t, tc.wantPass, got.Password.Value)
		})
	}
}

func TestCoreGetBMC(t *testing.T) {
	mac := parseMAC(t, "aa:bb:cc:dd:ee:ff")

	t.Run("credential is returned", func(t *testing.T) {
		srv := &fakeForge{bmcResp: usernamePasswordResponse("root", "secret")}
		mgr := newTestCoreManager(t, srv)

		got, err := mgr.GetBMC(context.Background(), mac)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, mac.String(), srv.gotBmcMac)
		assert.Equal(t, "root", got.User)
		assert.Equal(t, "secret", got.Password.Value)
	})

	t.Run("not found maps to ErrNotFound", func(t *testing.T) {
		srv := &fakeForge{bmcErr: status.Error(codes.NotFound, "switch_bmc_credentials")}
		mgr := newTestCoreManager(t, srv)

		got, err := mgr.GetBMC(context.Background(), mac)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestCoreConfigValidate(t *testing.T) {
	testCases := map[string]struct {
		cfg     CoreConfig
		wantErr bool
	}{
		"address set validates":     {cfg: CoreConfig{Address: "nico-api:50051"}},
		"empty address is rejected": {cfg: CoreConfig{}, wantErr: true},
		"blank address is rejected": {cfg: CoreConfig{Address: "   "}, wantErr: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestCoreConfigTimeoutDefaults(t *testing.T) {
	assert.Equal(t, defaultGRPCTimeout, CoreConfig{}.timeout())
	assert.Equal(t, 2*time.Second, CoreConfig{Timeout: 2 * time.Second}.timeout())

	// Only zero is "unset". A negative is a misconfiguration, so it is rejected
	// by Validate rather than passed through timeout() as the default.
	assert.Error(t, (&CoreConfig{Address: "nico-api:50051", Timeout: -1}).Validate())
	assert.NoError(t, (&CoreConfig{Address: "nico-api:50051"}).Validate())
}
