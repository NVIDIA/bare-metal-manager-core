// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"fmt"

	"github.com/PagerDuty/go-pagerduty"
)

// PagerDutyClient wraps the official PagerDuty client for sending events
type PagerDutyClient struct {
	integrationKey string
}

// SendPagerDutyAlertWithDedupeKey sends a critical alert to PagerDuty with a custom deduplication key
func (pc PagerDutyClient) SendPagerDutyAlertWithDedupeKey(ctx context.Context, summary, source, dedupKey string, customDetails map[string]string) error {
	event := pagerduty.V2Event{
		RoutingKey: pc.integrationKey,
		Action:     "trigger",
		DedupKey:   dedupKey,
		Payload: &pagerduty.V2Payload{
			Summary:  summary,
			Source:   source,
			Severity: "critical",
			Details:  customDetails,
		},
	}

	resp, err := pagerduty.ManageEventWithContext(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to send PagerDuty event: %w", err)
	}

	if resp.Status != "success" {
		return fmt.Errorf("PagerDuty event not successful: %s", resp.Status)
	}

	return nil
}

// NewPagerDutyClient creates a new PagerDuty client wrapper
func NewPagerDutyClient(integrationKey string) PagerDutyClient {
	return PagerDutyClient{
		integrationKey: integrationKey,
	}
}
