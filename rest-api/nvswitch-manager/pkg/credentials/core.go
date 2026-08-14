// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/credential"
	"github.com/NVIDIA/infra-controller/rest-api/nvswitch-manager/internal/certs"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// defaultGRPCTimeout bounds a single credential lookup. Credentials are read
// on the path of every device operation, so a hung Core connection must fail
// the operation rather than stall the worker holding it.
const defaultGRPCTimeout = 30 * time.Second

// CoreConfig configures access to NICo Core, which owns switch credentials.
type CoreConfig struct {
	// Address is the host:port of the Core gRPC API.
	Address string
	// Timeout bounds a single lookup; zero means defaultGRPCTimeout.
	Timeout time.Duration
}

// String returns a loggable form of the config.
func (c CoreConfig) String() string {
	return fmt.Sprintf("Core Address: %s; Timeout: %s", c.Address, c.timeout())
}

func (c CoreConfig) timeout() time.Duration {
	// Only zero means "unset". A negative is a misconfiguration that Validate
	// rejects, rather than something quietly read as the default.
	if c.Timeout == 0 {
		return defaultGRPCTimeout
	}
	return c.Timeout
}

// Validate ensures required Core fields are provided.
func (c *CoreConfig) Validate() error {
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("invalid core api address specified")
	}
	if c.Timeout < 0 {
		return fmt.Errorf("invalid core api timeout specified: %s is negative", c.Timeout)
	}
	return nil
}

// CoreCredentialManager reads switch credentials from NICo Core over mTLS
// gRPC. Core stores them envelope-encrypted in Postgres and rotates them, so
// every lookup goes to Core: caching here would serve a password that rotation
// has already replaced.
type CoreCredentialManager struct {
	client  corev1.ForgeClient
	conn    *grpc.ClientConn
	timeout time.Duration
}

// NewManager dials Core using the pod's SPIFFE certificates. grpc.NewClient is
// lazy, so a failure here means the config or certs are wrong, not that Core
// is down.
func (c *CoreConfig) NewManager() (*CoreCredentialManager, error) {
	// Re-checked here rather than trusted from the caller, so a blank address
	// surfaces as a config error instead of a dial failure later on.
	if err := c.Validate(); err != nil {
		return nil, err
	}

	tlsConfig, _, err := certs.TLSConfig()
	if err != nil {
		if errors.Is(err, certs.ErrNotPresent) {
			return nil, errors.New("certificates not present, unable to authenticate with nico-core-api")
		}
		return nil, err
	}

	conn, err := grpc.NewClient(c.Address, grpc.WithTransportCredentials(grpccreds.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("unable to connect to nico-core-api at %s: %w", c.Address, err)
	}

	return &CoreCredentialManager{
		client:  corev1.NewForgeClient(conn),
		conn:    conn,
		timeout: c.timeout(),
	}, nil
}

// Start is a no-op: the gRPC connection is established lazily on first use.
func (m *CoreCredentialManager) Start(ctx context.Context) error {
	log.Printf("Starting NICo Core credential manager")
	return nil
}

// Stop closes the gRPC connection.
func (m *CoreCredentialManager) Stop(ctx context.Context) error {
	log.Printf("Stopping NICo Core credential manager")
	if m.conn == nil {
		return nil
	}
	return m.conn.Close()
}

// GetBMC retrieves the switch BMC's root credential from Core.
func (m *CoreCredentialManager) GetBMC(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	resp, err := m.client.GetSwitchBmcCredentials(ctx, &corev1.GetSwitchBmcCredentialsRequest{
		BmcMacAddr: mac.String(),
	})
	return credentialFromResponse("BMC", mac, resp, err)
}

// GetNVOS retrieves the switch's NVOS admin credential from Core.
func (m *CoreCredentialManager) GetNVOS(ctx context.Context, mac net.HardwareAddr) (*credential.Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// switch_id is left unset: NSM keys switches by BMC MAC and holds no
	// Carbide SwitchId. Core rejects a request carrying both.
	resp, err := m.client.GetSwitchNvosCredentials(ctx, &corev1.GetSwitchNvosCredentialsRequest{
		BmcMacAddr: proto.String(mac.String()),
	})
	return credentialFromResponse("NVOS", mac, resp, err)
}

// credentialFromResponse converts a Core credential response into a
// Credential, mapping a NotFound status to ErrNotFound so callers can
// distinguish an unprovisioned switch from an unreachable Core.
//
// kind is "BMC" or "NVOS" purely for error readability.
func credentialFromResponse(
	kind string,
	mac net.HardwareAddr,
	resp *corev1.GetBmcCredentialsResponse,
	err error,
) (*credential.Credential, error) {
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("%s credential for %s: %w", kind, mac, ErrNotFound)
		}
		return nil, fmt.Errorf("reading %s credential for %s from core: %w", kind, mac, err)
	}

	// Core answers BMC credential requests with either a username/password or
	// a Redfish session token. Switch credentials are always the former, so a
	// token here means the request was routed to the wrong Core handler.
	up := resp.GetCredentials().GetUsernamePassword()
	if up == nil {
		return nil, fmt.Errorf("core returned no username/password %s credential for %s", kind, mac)
	}

	cred := credential.New(up.GetUsername(), up.GetPassword())
	if !cred.IsValid() {
		return nil, fmt.Errorf("core returned an invalid %s credential for %s", kind, mac)
	}

	return &cred, nil
}
