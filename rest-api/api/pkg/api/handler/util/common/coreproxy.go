// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"

	"github.com/google/uuid"
	temporalEnums "go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

// ExecuteCoreGRPC proxies one already-validated NICo Core (forge.Forge) gRPC
// request via the generic site proxy workflow (coreproxy.WorkflowName). A REST
// handler may call this helper zero, one, or many times depending on how many
// Core invocations it needs. The caller supplies the typed request proto; it is
// protojson-encoded for transport so it is readable in the Temporal UI, and the
// protojson response is decoded into resp (which may be nil for methods with an
// empty response).
//
// It returns an HTTP status code appropriate for the outcome (http.StatusOK on
// success) so the handler can surface a consistent error response.
func ExecuteCoreGRPC(ctx context.Context, stc tclient.Client, fullMethod string, req proto.Message, resp proto.Message, secretKey string, secretFields ...string) (int, error) {
	reqJSON, err := protojson.Marshal(req)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("encode request for %s: %w", fullMethod, err)
	}

	// Redact any secret fields from the Temporal-visible request and carry them
	// AES-encrypted so they never appear in Temporal history in cleartext. The
	// site decrypts with the same key (the site ID) and merges them back.
	var encryptedSecrets []byte
	if secretKey != "" && len(secretFields) > 0 {
		redacted, secretsJSON, rerr := coreproxy.RedactSecrets(reqJSON, secretFields)
		if rerr != nil {
			return http.StatusInternalServerError, rerr
		}
		reqJSON = redacted
		if len(secretsJSON) > 0 {
			encryptedSecrets = cutil.EncryptData(secretsJSON, secretKey)
		}
	}

	workflowID := fmt.Sprintf("core-grpc-%s-%s", path.Base(fullMethod), uuid.NewString())
	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       workflowID,
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDReusePolicy:    temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
	}

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, workflowOptions, coreproxy.WorkflowName, coreproxy.Request{
		FullMethod:       fullMethod,
		RequestJSON:      reqJSON,
		EncryptedSecrets: encryptedSecrets,
	})
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("execute %s workflow: %w", coreproxy.WorkflowName, err)
	}

	var out coreproxy.Response
	if err := we.Get(wfCtx, &out); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || errors.Is(err, context.DeadlineExceeded) || wfCtx.Err() != nil {
			return http.StatusGatewayTimeout, fmt.Errorf("core proxy %s timed out: %w", fullMethod, err)
		}
		code, werr := UnwrapWorkflowError(err)
		return code, werr
	}

	if resp != nil && len(out.ResponseJSON) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(out.ResponseJSON, resp); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("decode response for %s: %w", fullMethod, err)
		}
	}
	return http.StatusOK, nil
}
