// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"

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
	Enriched enrichment
	Rule     *eventrule.Rule
}

// prepare enriches an envelope and resolves its effective rule. An absent rule
// is an accepted no-op represented by a nil preparedEvent.Rule.
func (p *Processor) prepare(
	ctx context.Context,
	envelope eventrule.Envelope,
) (preparedEvent, error) {
	if err := envelope.Validate(); err != nil {
		return preparedEvent{}, terminalError(err)
	}

	enriched, err := p.enrich(ctx, envelope)
	if err != nil {
		return preparedEvent{}, err
	}

	rule, err := p.rules.GetEffective(
		ctx,
		envelope.Type,
		enriched.ResolvedResource.RackID,
	)
	if err != nil {
		return preparedEvent{}, classifyRuleError(err)
	}

	return preparedEvent{
		Envelope: envelope,
		Enriched: enriched,
		Rule:     rule,
	}, nil
}
