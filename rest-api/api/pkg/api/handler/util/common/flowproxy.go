// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	temporalEnums "go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/flowproxy"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/secretjson"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

// ExecuteFlowGRPC proxies one already-validated Flow (v1.Flow) gRPC request via
// the generic site proxy workflow (flowproxy.WorkflowName). Unlike
// ExecuteCoreGRPC, the caller supplies the Temporal workflow ID and conflict
// policy so handlers can keep read dedup (deterministic IDs + USE_EXISTING) and
// create freshness (per-request UUIDs) without a bespoke workflow per method.
//
// The caller supplies the typed request proto; it is protojson-encoded for
// transport so it is readable in the Temporal UI, and the protojson response is
// decoded into resp (which may be nil for methods with an empty response).
//
// It returns an APIError when the proxy request fails so handlers can surface
// the status code and message without replacing Flow/Temporal details with a
// generic wrapper. On timeout it returns StatusGatewayTimeout; handlers that
// previously terminated the workflow on timeout should call
// TerminateWorkflowOnTimeOut with the same workflowID.
func ExecuteFlowGRPC(
	ctx context.Context,
	stc tclient.Client,
	fullMethod string,
	req proto.Message,
	resp proto.Message,
	workflowID string,
	conflictPolicy temporalEnums.WorkflowIdConflictPolicy,
	secretKey string,
	secretFields ...string,
) *cutil.APIError {
	reqJSON, err := protojson.Marshal(req)
	if err != nil {
		return cutil.NewAPIError(http.StatusInternalServerError, "Failed to encode Flow proxy request", fmt.Errorf("encode request for %s: %w", fullMethod, err))
	}

	// Redact any secret fields from the Temporal-visible request and carry them
	// AES-encrypted so they never appear in Temporal history in cleartext. The
	// site decrypts with the same key (the site ID) and merges them back.
	var encryptedSecrets []byte
	if secretKey != "" && len(secretFields) > 0 {
		redacted, secretsJSON, rerr := secretjson.Redact(reqJSON, secretFields)
		if rerr != nil {
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to redact Flow proxy request", rerr)
		}
		reqJSON = redacted
		if len(secretsJSON) > 0 {
			encryptedSecrets = cutil.EncryptData(secretsJSON, secretKey)
		}
	}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       workflowID,
		WorkflowExecutionTimeout: flowproxy.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDReusePolicy:    temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
		WorkflowIDConflictPolicy: conflictPolicy,
	}

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, workflowOptions, flowproxy.WorkflowName, flowproxy.Request{
		FullMethod:       fullMethod,
		RequestJSON:      reqJSON,
		EncryptedSecrets: encryptedSecrets,
	})
	if err != nil {
		return cutil.NewAPIError(http.StatusInternalServerError, "Failed to execute Flow proxy workflow", fmt.Errorf("execute %s workflow: %w", flowproxy.WorkflowName, err))
	}

	var out flowproxy.Response
	if err := we.Get(wfCtx, &out); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || errors.Is(err, context.DeadlineExceeded) || wfCtx.Err() != nil {
			return cutil.NewAPIError(http.StatusGatewayTimeout, "Flow proxy request timed out", fmt.Errorf("flow proxy %s timed out: %w", fullMethod, err))
		}
		code, werr := UnwrapWorkflowError(err)
		return cutil.NewAPIError(code, werr.Error(), nil)
	}

	if resp != nil && len(out.ResponseJSON) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(out.ResponseJSON, resp); err != nil {
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to decode Flow proxy response", fmt.Errorf("decode response for %s: %w", fullMethod, err))
		}
	}
	return nil
}
