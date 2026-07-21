// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	"github.com/google/uuid"
	workflowservice "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/server/common/api"
	"go.temporal.io/server/common/authorization"
)

const (
	cloudNamespace = "cloud"
	siteNamespace  = "site"
	flowNamespace  = "flow"
)

type authorizer struct {
	defaultAuthorizer authorization.Authorizer
}

var _ authorization.Authorizer = (*authorizer)(nil)

func NewAuthorizer() authorization.Authorizer {
	return &authorizer{defaultAuthorizer: authorization.NewDefaultAuthorizer()}
}

func (a *authorizer) Authorize(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	if authorization.IsHealthCheckAPI(target.APIName) {
		return allow(), nil
	}

	callerIdentity, ok := identityFromClaims(claims)
	if !ok {
		return deny(), nil
	}

	switch callerIdentity.kind {
	case identityAdmin:
		return allow(), nil
	case identityControl:
		return a.authorizeControl(ctx, claims, target)
	case identitySite:
		return a.authorizeNamespaces(ctx, claims, target, siteNamespace, callerIdentity.siteNamespace)
	case identityFlow:
		return a.authorizeNamespaces(ctx, claims, target, flowNamespace)
	default:
		return deny(), nil
	}
}

func (a *authorizer) authorizeControl(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	metadata := api.GetMethodMetadata(target.APIName)
	if metadata.Scope == api.ScopeCluster && metadata.Access == api.AccessReadOnly {
		return a.defaultAuthorizer.Authorize(ctx, withSystemRole(claims, authorization.RoleReader), target)
	}
	if target.APIName == workflowservice.WorkflowService_RegisterNamespace_FullMethodName && isSiteNamespace(target.Namespace) {
		return allow(), nil
	}
	if target.Namespace != cloudNamespace && target.Namespace != siteNamespace && !isSiteNamespace(target.Namespace) {
		return deny(), nil
	}
	return a.defaultAuthorizer.Authorize(ctx, withNamespaceRole(claims, target.Namespace), target)
}

func (a *authorizer) authorizeNamespaces(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget, namespaces ...string) (authorization.Result, error) {
	for _, namespace := range namespaces {
		if target.Namespace == namespace {
			return a.defaultAuthorizer.Authorize(ctx, withNamespaceRole(claims, namespace), target)
		}
	}
	return deny(), nil
}

func identityFromClaims(claims *authorization.Claims) (identity, bool) {
	if claims == nil {
		return identity{}, false
	}
	callerIdentity, ok := claims.Extensions.(identity)
	return callerIdentity, ok
}

func withSystemRole(claims *authorization.Claims, role authorization.Role) *authorization.Claims {
	return &authorization.Claims{
		Subject:    claims.Subject,
		System:     role,
		Namespaces: claims.Namespaces,
		Extensions: claims.Extensions,
	}
}

func withNamespaceRole(claims *authorization.Claims, namespace string) *authorization.Claims {
	return &authorization.Claims{
		Subject:    claims.Subject,
		Namespaces: map[string]authorization.Role{namespace: authorization.RoleWriter},
		Extensions: claims.Extensions,
	}
}

func isSiteNamespace(namespace string) bool {
	parsedNamespace, err := uuid.Parse(namespace)
	return err == nil && parsedNamespace.String() == namespace
}

func allow() authorization.Result {
	return authorization.Result{Decision: authorization.DecisionAllow}
}

func deny() authorization.Result {
	return authorization.Result{Decision: authorization.DecisionDeny}
}
