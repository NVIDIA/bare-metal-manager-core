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

// preparedEvent contains the durable event definition and the transient
// resolved resource needed by creator-owned planning.
type preparedEvent struct {
	Event    eventrule.Event
	Resource eventrule.ResolvedResource
}

// prepare admits a creator-owned event for planning. It deduplicates before
// performing preparation work, enriches the resource, resolves and evaluates
// the effective rule, and persists the event. A duplicate or absent rule is an
// accepted no-op represented by (nil, nil).
func (p *Processor) prepare(
	ctx context.Context,
	envelope eventrule.Envelope,
) (*preparedEvent, error) {
	if err := envelope.Validate(); err != nil {
		return nil, terminalError(err)
	}

	// ObserveEvent is the duplicate fast path before resource enrichment and
	// rule resolution. It records the duplicate observation while avoiding the
	// preparation cost. Recovery of unplanned events is follow-on work.
	observed, err := p.events.ObserveEvent(ctx, envelope.Key)
	if err != nil || observed != nil {
		// Propagate lookup errors; a successfully observed duplicate stops here
		// because its creator retains responsibility for planning and dispatch.
		return nil, err
	}

	resource, err := p.enrich(ctx, envelope)
	if err != nil {
		return nil, err
	}

	rule, err := p.rules.GetEffective(
		ctx,
		envelope.Type,
		resource.RackID,
	)
	if err != nil || rule == nil {
		return nil, classifyRuleError(err)
	}

	applicable := make([]eventrule.Action, 0, len(rule.Actions))
	for _, action := range rule.Actions {
		if action.Condition.AppliesTo(envelope, resource) {
			applicable = append(applicable, action.Clone())
		}
	}

	// Persist an empty effective policy to record that the rule was evaluated
	// and no action applied. This keeps duplicate handling stable and lets the
	// planning checkpoint distinguish an intentional no-op from interrupted work.
	definition := eventrule.Event{
		Key:           envelope.Key,
		Type:          envelope.Type,
		Resource:      eventrule.ResourceIdentity{Kind: resource.Kind, ID: resource.ID},
		AppliedRuleID: rule.ID,
		EffectivePolicy: eventrule.Policy{
			Actions: applicable,
		},
		Summary: fmt.Sprintf(
			"%s on %s %s",
			envelope.Type,
			resource.Kind,
			resource.ID,
		),
	}

	created, err := p.events.CreateEvent(ctx, definition)
	if err != nil || created == nil {
		// A nil event means another processor created it between ObserveEvent and
		// CreateEvent. The store recorded this delivery as a duplicate, so stop here.
		return nil, err
	}

	return &preparedEvent{Event: *created, Resource: resource}, nil
}
