// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psmapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/certs"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi/gen"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type grpcClient struct {
	conn        *grpc.ClientConn
	client      pb.PowershelfManagerClient
	grpcTimeout time.Duration
}

var testingMsgOnce sync.Once

// NewClient creates a GRPC connection pool to PSM. Returning success does not mean that we have yet made an actual connection;
// that happens when making an actual request.
func NewClient(grpcTimeout time.Duration) (Client, error) {
	if testing.Testing() {
		testingMsgOnce.Do(func() {
			log.Info().Msg("Running unit tests, forcing mock GRPC client for PSM")
		})
		return NewMockClient(), nil
	}

	psmURL := os.Getenv("PSM_API_URL")
	if psmURL == "" {
		return nil, errors.New("PSM_API_URL not set, cannot make connections to PSM")
	}

	tlsConfig, _, err := certs.TLSConfig()
	if err != nil {
		if err == certs.ErrNotPresent {
			return nil, errors.New("Certificates not present, unable to authenticate with PSM")
		}
		return nil, err
	}

	conn, err := grpc.NewClient(psmURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to PSM: %w", err)
	}

	return &grpcClient{
		conn:        conn,
		client:      pb.NewPowershelfManagerClient(conn),
		grpcTimeout: grpcTimeout,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *grpcClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetPowershelves returns powershelf information for the specified PMC MAC addresses.
func (c *grpcClient) GetPowershelves(ctx context.Context, pmcMacs []string) ([]PowerShelf, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.GetPowershelves(ctx, &pb.PowershelfRequest{PmcMacs: pmcMacs})
	if err != nil {
		return nil, err
	}

	var result []PowerShelf
	for _, ps := range resp.Powershelves {
		result = append(result, powerShelfFromPb(ps))
	}
	return result, nil
}

// RegisterPowershelves registers new powershelves with their PMC credentials.
func (c *grpcClient) RegisterPowershelves(ctx context.Context, requests []RegisterPowershelfRequest) ([]RegisterPowershelfResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbRequests := make([]*pb.RegisterPowershelfRequest, 0, len(requests))
	for _, req := range requests {
		pbRequests = append(pbRequests, registerPowershelfRequestToPb(req))
	}

	resp, err := c.client.RegisterPowershelves(ctx, &pb.RegisterPowershelvesRequest{RegistrationRequests: pbRequests})
	if err != nil {
		return nil, err
	}

	var result []RegisterPowershelfResponse
	for _, r := range resp.Responses {
		result = append(result, registerPowershelfResponseFromPb(r))
	}
	return result, nil
}

// PowerOn powers on the specified powershelves.
func (c *grpcClient) PowerOn(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.PowerOn(ctx, &pb.PowershelfRequest{PmcMacs: pmcMacs})
	if err != nil {
		return nil, err
	}

	var result []PowerControlResult
	for _, r := range resp.Responses {
		result = append(result, powerControlResultFromPb(r))
	}
	return result, nil
}

// PowerOff powers off the specified powershelves.
func (c *grpcClient) PowerOff(ctx context.Context, pmcMacs []string) ([]PowerControlResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.PowerOff(ctx, &pb.PowershelfRequest{PmcMacs: pmcMacs})
	if err != nil {
		return nil, err
	}

	var result []PowerControlResult
	for _, r := range resp.Responses {
		result = append(result, powerControlResultFromPb(r))
	}
	return result, nil
}

// UpdateFirmware performs firmware upgrades on the specified powershelves.
func (c *grpcClient) UpdateFirmware(ctx context.Context, requests []UpdatePowershelfFirmwareRequest) ([]UpdatePowershelfFirmwareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbRequests := make([]*pb.UpdatePowershelfFirmwareRequest, 0, len(requests))
	for _, req := range requests {
		pbRequests = append(pbRequests, updatePowershelfFirmwareRequestToPb(req))
	}

	resp, err := c.client.UpdateFirmware(ctx, &pb.UpdateFirmwareRequest{Upgrades: pbRequests})
	if err != nil {
		return nil, err
	}

	var result []UpdatePowershelfFirmwareResponse
	for _, r := range resp.Responses {
		result = append(result, updatePowershelfFirmwareResponseFromPb(r))
	}
	return result, nil
}

// GetFirmwareUpdateStatus returns the status of firmware updates for the specified PMC(s) and component(s).
func (c *grpcClient) GetFirmwareUpdateStatus(ctx context.Context, queries []FirmwareUpdateQuery) ([]FirmwareUpdateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbQueries := make([]*pb.FirmwareUpdateQuery, 0, len(queries))
	for _, q := range queries {
		pbQueries = append(pbQueries, firmwareUpdateQueryToPb(q))
	}

	resp, err := c.client.GetFirmwareUpdateStatus(ctx, &pb.GetFirmwareUpdateStatusRequest{Queries: pbQueries})
	if err != nil {
		return nil, err
	}

	var result []FirmwareUpdateStatus
	for _, s := range resp.Statuses {
		result = append(result, firmwareUpdateStatusFromPb(s))
	}
	return result, nil
}

// ListAvailableFirmware lists the firmware versions available for the specified powershelves.
func (c *grpcClient) ListAvailableFirmware(ctx context.Context, pmcMacs []string) ([]AvailableFirmware, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.ListAvailableFirmware(ctx, &pb.PowershelfRequest{PmcMacs: pmcMacs})
	if err != nil {
		return nil, err
	}

	var result []AvailableFirmware
	for _, a := range resp.Upgrades {
		result = append(result, availableFirmwareFromPb(a))
	}
	return result, nil
}

// SetDryRun configures whether the firmware manager is in Dry Run mode.
func (c *grpcClient) SetDryRun(ctx context.Context, dryRun bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	_, err := c.client.SetDryRun(ctx, &pb.SetDryRunRequest{DryRun: dryRun})
	return err
}

// AddPowershelf is only valid in the mock environment.
func (c *grpcClient) AddPowershelf(PowerShelf) {
	panic("Not a unit test")
}
