// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
)

// RuleResolver resolves the effective rule for an event and rack scope.
// A cache may decorate this interface without changing processing.
type RuleResolver interface {
	GetEffective(context.Context, eventrule.Type, uuid.UUID) (*eventrule.Rule, error)
}

// preparedEvent contains runtime inputs prepared for policy evaluation.
type preparedEvent struct {
	Envelope eventrule.Envelope
	Resource eventrule.ResolvedResource
	Rule     *eventrule.Rule
}

// prepare enriches an envelope, resolves its effective rule, and validates
// event-rule runtime compatibility. An absent rule is an accepted no-op
// represented by a nil preparedEvent.Rule.
func (p *Processor) prepare(
	ctx context.Context,
	envelope eventrule.Envelope,
) (preparedEvent, error) {
	if err := envelope.Validate(); err != nil {
		return preparedEvent{}, terminalError(err)
	}

	resource, err := p.enrich(ctx, envelope)
	if err != nil {
		return preparedEvent{}, err
	}

	rule, err := p.rules.GetEffective(
		ctx,
		envelope.Type,
		resource.RackID,
	)
	if err != nil {
		return preparedEvent{}, classifyRuleError(err)
	}

	if rule != nil && rule.Dedupe != nil && envelope.CorrelationKey == "" {
		return preparedEvent{}, terminalError(fmt.Errorf(
			"correlation key is required by rule %s dedupe policy",
			rule.ID,
		))
	}

	return preparedEvent{
		Envelope: envelope,
		Resource: resource,
		Rule:     rule,
	}, nil
}
