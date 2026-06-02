// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nsmapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/certs"
	pb "github.com/NVIDIA/infra-controller-rest/flow/internal/nsmapi/gen"
)

type grpcClient struct {
	conn        *grpc.ClientConn
	client      pb.NVSwitchManagerClient
	grpcTimeout time.Duration
}

// NewClient creates a gRPC connection pool to NV-Switch Manager. Returning success does not mean that we have yet
// made an actual connection; that happens when making an actual request.
func NewClient(grpcTimeout time.Duration) (Client, error) {
	nsmURL := os.Getenv("NSM_API_URL")
	if nsmURL == "" {
		return nil, errors.New("NSM_API_URL not set, cannot make connections to NV-Switch Manager")
	}

	tlsConfig, _, err := certs.TLSConfig()
	if err != nil {
		if err == certs.ErrNotPresent {
			return nil, errors.New("Certificates not present, unable to authenticate with NV-Switch Manager")
		}
		return nil, err
	}

	conn, err := grpc.NewClient(nsmURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to NV-Switch Manager: %w", err)
	}

	return &grpcClient{
		conn:        conn,
		client:      pb.NewNVSwitchManagerClient(conn),
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

// GetNVSwitches returns NV-Switch information for the specified switch UUIDs.
func (c *grpcClient) GetNVSwitches(ctx context.Context, uuids []string) ([]NVSwitchTray, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.GetNVSwitches(ctx, &pb.NVSwitchRequest{
		Uuids: uuids,
	})
	if err != nil {
		return nil, err
	}

	var results []NVSwitchTray
	for _, tray := range resp.GetNvswitches() {
		results = append(results, nvSwitchTrayFromPb(tray))
	}
	return results, nil
}

// RegisterNVSwitches registers NV-Switch trays and returns service-generated UUIDs.
func (c *grpcClient) RegisterNVSwitches(ctx context.Context, requests []RegisterNVSwitchRequest) ([]RegisterNVSwitchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbRequests := make([]*pb.RegisterNVSwitchRequest, 0, len(requests))
	for _, req := range requests {
		pbRequests = append(pbRequests, &pb.RegisterNVSwitchRequest{
			Vendor: pb.Vendor_VENDOR_NVIDIA,
			Bmc: &pb.Subsystem{
				MacAddress: req.BMCMACAddress,
				IpAddress:  req.BMCIPAddress,
			},
			Nvos: &pb.Subsystem{
				MacAddress: req.NVOSMACAddress,
				IpAddress:  req.NVOSIPAddress,
			},
		})
	}

	resp, err := c.client.RegisterNVSwitches(ctx, &pb.RegisterNVSwitchesRequest{
		RegistrationRequests: pbRequests,
	})
	if err != nil {
		return nil, err
	}

	var results []RegisterNVSwitchResponse
	for _, r := range resp.GetResponses() {
		results = append(results, registerNVSwitchResponseFromPb(r))
	}
	return results, nil
}

func (c *grpcClient) AddNVSwitch(_ NVSwitchTray) {
	panic("Not a unit test")
}

func (c *grpcClient) SetNVSwitchFirmware(_ string, _ string) {
	panic("Not a unit test")
}

// PowerControl performs a power action on the specified NV-Switch trays.
func (c *grpcClient) PowerControl(ctx context.Context, uuids []string, action PowerAction) ([]PowerControlResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.PowerControl(ctx, &pb.PowerControlRequest{
		Uuids:  uuids,
		Action: powerActionToPb(action),
	})
	if err != nil {
		return nil, err
	}

	var results []PowerControlResult
	for _, r := range resp.GetResponses() {
		results = append(results, powerControlResultFromPb(r))
	}
	return results, nil
}

// QueueUpdates queues firmware updates for one or more components for multiple switches.
func (c *grpcClient) QueueUpdates(ctx context.Context, switchUUIDs []string, bundleVersion string, components []NVSwitchComponent) ([]FirmwareUpdateInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	pbComponents := make([]pb.NVSwitchComponent, 0, len(components))
	for _, comp := range components {
		pbComponents = append(pbComponents, nvSwitchComponentToPb(comp))
	}

	resp, err := c.client.QueueUpdates(ctx, &pb.QueueUpdatesRequest{
		SwitchUuids:   switchUUIDs,
		BundleVersion: bundleVersion,
		Components:    pbComponents,
	})

	if err != nil {
		return nil, err
	}

	var results []FirmwareUpdateInfo
	for _, info := range resp.GetResults() {
		if info.Status != pb.StatusCode_SUCCESS {
			results = append(results, FirmwareUpdateInfo{
				ErrorMessage: fmt.Sprintf("failed to queue firmware update to %s for Switch %s with StatusCode %s", bundleVersion, info.GetSwitchUuid(), info.Status.String()),
			})
			continue
		}

		for _, update := range info.GetUpdates() {
			results = append(results, firmwareUpdateInfoFromPb(update))
		}
	}

	return results, nil
}

// GetUpdates return the firmware status updates for a given switch.
func (c *grpcClient) GetUpdates(ctx context.Context, switchUuid string) ([]FirmwareUpdateInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.GetUpdatesForSwitch(ctx, &pb.GetUpdatesForSwitchRequest{
		SwitchUuid: switchUuid,
	})
	if err != nil {
		return nil, err
	}

	var ret []FirmwareUpdateInfo
	for _, update := range resp.Updates {
		ret = append(ret, firmwareUpdateInfoFromPb(update))
	}

	return ret, nil
}

// ListBundles returns all available firmware bundles.
func (c *grpcClient) ListBundles(ctx context.Context) ([]FirmwareBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, c.grpcTimeout)
	defer cancel()

	resp, err := c.client.ListBundles(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	var results []FirmwareBundle
	for _, bundle := range resp.GetBundles() {
		results = append(results, firmwareBundleFromPb(bundle))
	}
	return results, nil
}
