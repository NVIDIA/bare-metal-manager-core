// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"fmt"
	"sync"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

type resolverKey struct {
	eventType eventrule.Type
	strategy  eventrule.TargetStrategy
}

// Registry dispatches generic and event-specific target strategies.
type Registry struct {
	mu            sync.RWMutex
	generic       map[eventrule.TargetStrategy]ResolverFunc
	eventSpecific map[resolverKey]ResolverFunc
}

// New constructs a registry containing the generic component, rack, and
// affected-components strategies.
func New() *Registry {
	return &Registry{
		generic: map[eventrule.TargetStrategy]ResolverFunc{
			eventrule.TargetStrategyComponent:          resolveComponent,
			eventrule.TargetStrategyRack:               resolveRack,
			eventrule.TargetStrategyAffectedComponents: resolveAffectedComponents,
		},
		eventSpecific: make(map[resolverKey]ResolverFunc),
	}
}

// Register associates an event-specific strategy with its resolver. An
// event-specific resolver takes precedence over the generic strategy resolver.
func (r *Registry) Register(
	eventType eventrule.Type,
	strategy eventrule.TargetStrategy,
	resolver ResolverFunc,
) error {
	if r == nil {
		return fmt.Errorf("target resolver registry is nil")
	}
	if err := eventType.Validate(); err != nil {
		return err
	}
	if err := strategy.Validate(); err != nil {
		return err
	}
	if !strategy.RequiresResolution() {
		return fmt.Errorf("target strategy %q does not require resolution", strategy)
	}
	if resolver == nil {
		return fmt.Errorf("target resolver is required")
	}

	key := resolverKey{eventType: eventType, strategy: strategy}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.eventSpecific[key]; exists {
		return fmt.Errorf(
			"target resolver already registered for event type %q and strategy %q",
			eventType,
			strategy,
		)
	}
	r.eventSpecific[key] = resolver
	return nil
}

// Resolve dispatches a request to its generic or event-specific target
// resolver.
func (r *Registry) Resolve(
	ctx context.Context,
	request ResolveRequest,
) ([]Target, error) {
	if r == nil {
		return nil, fmt.Errorf("target resolver registry is nil")
	}

	if err := request.Resource.Validate(); err != nil {
		return nil, fmt.Errorf("%w: target resource: %v", ErrUnresolvable, err)
	}

	resolver := r.resolver(request.Envelope.Type, request.Strategy)
	if resolver == nil {
		return nil, fmt.Errorf(
			"%w: "+
				"no target resolver for event type %q and strategy %q",
			ErrUnresolvable,
			request.Envelope.Type,
			request.Strategy,
		)
	}

	targets, err := resolver(ctx, request)
	if err != nil {
		return nil, err
	}
	for i, resolved := range targets {
		if err := resolved.Validate(); err != nil {
			return nil, fmt.Errorf(
				"%w: resolver target %d: %v",
				ErrUnresolvable,
				i,
				err,
			)
		}
	}

	return targets, nil
}

// ValidateRule checks that every task action in a valid rule has a registered
// target resolver.
func (r *Registry) ValidateRule(rule *eventrule.Rule) error {
	if r == nil {
		return fmt.Errorf("target resolver registry is nil")
	}

	if err := rule.Validate(); err != nil {
		return err
	}

	for _, action := range rule.Actions {
		strategy := action.Spec.TargetResolutionStrategy()
		if !strategy.RequiresResolution() {
			continue
		}
		if r.resolver(rule.EventType, strategy) == nil {
			return fmt.Errorf(
				"event rule %s action %q has no target resolver for strategy %q",
				rule.ID,
				action.ID,
				strategy,
			)
		}
	}

	return nil
}

func (r *Registry) resolver(
	eventType eventrule.Type,
	strategy eventrule.TargetStrategy,
) ResolverFunc {
	key := resolverKey{eventType: eventType, strategy: strategy}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if resolver := r.eventSpecific[key]; resolver != nil {
		return resolver
	}

	return r.generic[strategy]
}

var _ Resolver = (*Registry)(nil)
