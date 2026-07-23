// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	workflowservice "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/server/common/authorization"
)

func TestAuthorizationPolicy(t *testing.T) {
	t.Parallel()

	const (
		ownSite   = "11111111-1111-1111-1111-111111111111"
		otherSite = "22222222-2222-2222-2222-222222222222"
	)
	tests := []struct {
		name         string
		caller       identity
		apiName      string
		namespace    string
		wantDecision authorization.Decision
	}{
		{
			name:         "unknown identity denied",
			caller:       identity{kind: identityUnknown},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "admin can call operator API",
			caller:       identity{kind: identityAdmin},
			apiName:      "/temporal.api.operatorservice.v1.OperatorService/DeleteNamespace",
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control can write cloud namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control can write site namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    siteNamespace,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control can write a site-specific namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    ownSite,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control cannot write flow namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    flowNamespace,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "control cannot write system namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    "temporal-system",
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "control can list namespaces",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_ListNamespaces_FullMethodName,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control can register site-specific namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_RegisterNamespace_FullMethodName,
			namespace:    ownSite,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "control cannot register shared namespace",
			caller:       identity{kind: identityControl},
			apiName:      workflowservice.WorkflowService_RegisterNamespace_FullMethodName,
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "control cannot call operator API",
			caller:       identity{kind: identityControl},
			apiName:      "/temporal.api.operatorservice.v1.OperatorService/DeleteNamespace",
			namespace:    ownSite,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "site can publish to shared site namespace",
			caller:       identity{kind: identitySite, siteNamespace: ownSite},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    siteNamespace,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "site can use own namespace",
			caller:       identity{kind: identitySite, siteNamespace: ownSite},
			apiName:      workflowservice.WorkflowService_PollWorkflowTaskQueue_FullMethodName,
			namespace:    ownSite,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "site cannot use another site namespace",
			caller:       identity{kind: identitySite, siteNamespace: ownSite},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    otherSite,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "site cannot use cloud namespace",
			caller:       identity{kind: identitySite, siteNamespace: ownSite},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "flow can use flow namespace",
			caller:       identity{kind: identityFlow},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    flowNamespace,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "flow cannot use site namespace",
			caller:       identity{kind: identityFlow},
			apiName:      workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
			namespace:    siteNamespace,
			wantDecision: authorization.DecisionDeny,
		},
	}

	policy := NewAuthorizer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := &authorization.Claims{Extensions: test.caller}
			result, err := policy.Authorize(context.Background(), claims, &authorization.CallTarget{
				APIName:   test.apiName,
				Namespace: test.namespace,
			})
			require.NoError(t, err)
			assert.Equal(t, test.wantDecision, result.Decision)
		})
	}
}

func TestMappedCertificatePolicy(t *testing.T) {
	t.Parallel()

	const siteID = "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name         string
		certificate  *x509.Certificate
		namespace    string
		wantDecision authorization.Decision
	}{
		{
			name:         "site certificate can use own namespace",
			certificate:  certificate(siteID+siteClientDNSSuffix, siteID+siteClientDNSSuffix),
			namespace:    siteID,
			wantDecision: authorization.DecisionAllow,
		},
		{
			name:         "site certificate cannot use flow namespace",
			certificate:  certificate(siteID+siteClientDNSSuffix, siteID+siteClientDNSSuffix),
			namespace:    flowNamespace,
			wantDecision: authorization.DecisionDeny,
		},
		{
			name:         "flow certificate cannot use cloud namespace",
			certificate:  certificate(clientCommonName, clientCommonName, flowDNSName),
			namespace:    cloudNamespace,
			wantDecision: authorization.DecisionDeny,
		},
	}

	mapper := NewClaimMapper()
	policy := NewAuthorizer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims, err := mapper.GetClaims(authInfo(test.certificate, true))
			require.NoError(t, err)
			result, err := policy.Authorize(context.Background(), claims, &authorization.CallTarget{
				APIName:   workflowservice.WorkflowService_StartWorkflowExecution_FullMethodName,
				Namespace: test.namespace,
			})
			require.NoError(t, err)
			assert.Equal(t, test.wantDecision, result.Decision)
		})
	}
}
