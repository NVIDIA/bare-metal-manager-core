// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
)

func resolveComponent(
	_ context.Context,
	request ResolveRequest,
) ([]Target, error) {
	resource := request.Resource
	if resource.Kind != eventrule.ResourceKindComponent {
		return nil, fmt.Errorf(
			"%w: "+
				"component target strategy requires a component resource, got %q",
			ErrUnresolvable,
			resource.Kind,
		)
	}
	return []Target{{
		Kind: eventrule.ResourceKindComponent,
		ID:   resource.ID,
	}}, nil
}

func resolveRack(
	_ context.Context,
	request ResolveRequest,
) ([]Target, error) {
	return []Target{{
		Kind: eventrule.ResourceKindRack,
		ID:   request.Resource.RackID,
	}}, nil
}

func resolveAffectedComponents(
	ctx context.Context,
	request ResolveRequest,
) ([]Target, error) {
	switch request.Resource.Kind {
	case eventrule.ResourceKindComponent:
		return resolveComponent(ctx, request)
	case eventrule.ResourceKindRack:
		return resolveRack(ctx, request)
	default:
		return nil, fmt.Errorf(
			"%w: "+
				"affected-components target strategy does not support resource kind %q",
			ErrUnresolvable,
			request.Resource.Kind,
		)
	}
}
