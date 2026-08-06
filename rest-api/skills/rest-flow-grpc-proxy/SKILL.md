---
name: rest-flow-grpc-proxy
description: Build or migrate infra-controller REST API endpoints that call on-site Flow through the generic Flow gRPC proxy. Use when working on REST-to-Flow operations, ExecuteFlowGRPC, grpcproxy, v1.Flow methods, or migrating bespoke TaskRun/Flow workflows to the gRPC proxy.
---

# REST Flow gRPC Proxy Skill

Use this guidance when building or converting `infra-controller` REST API
endpoints that need to call on-site Flow through the generic Flow gRPC proxy.

## Current Proxy Contract

- Cloud helper: `rest-api/api/pkg/api/handler/util/common/grpcproxy.go`,
  `ExecuteFlowGRPC`.
- Shared contract: `rest-api/common/pkg/grpcproxy/grpcproxy.go`, with
  `grpcproxy.Request` and `grpcproxy.Response`. Flow and Core share every layer
  of the proxy; the backend is named by `grpcproxy.Flow`, and each layer keeps a
  per-backend wrapper only because Temporal dispatches on the registered
  workflow and activity names.
- Site workflow/activity: `InvokeFlowGRPC` and `InvokeFlowGRPCOnSite`.
- Site Flow invocation: `FlowGrpcClient.InvokeJSON`.
- Temporal transport payload: protojson, so non-secret request fields and
  responses remain readable in Temporal UI.
- Secret transport payload: selected top-level protojson fields are redacted
  from `RequestJSON` and carried separately in `EncryptedSecrets`.
  `grpcproxy.RedactSecrets` / `grpcproxy.MergeSecrets` do the splitting and are
  shared with the Core proxy.
- Final site-to-Flow call: normal binary gRPC. The JSON step is only the
  generic Temporal payload representation.

## Critical Difference From CoreProxy

`ExecuteCoreGRPC` always generates a fresh workflow ID
(`core-grpc-{Method}-{uuid}`) and does not set `USE_EXISTING`.

`ExecuteFlowGRPC` requires the caller to supply:

1. `workflowID` — deterministic for read/list dedup, fresh UUID for creates.
2. `conflictPolicy` — typically `WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING`
   for Flow handlers that coalesce identical in-flight requests.

Kinds of ID derivation that must stay in the handler, using the TaskRun
endpoints as the worked example:

- A read whose response shape depends on a query flag must encode that flag, so
  `GetTaskRun` needs `includeStats` in the ID
  (`flow-grpc-task-run-get-{runID}-{true|false}`). Attaching to an execution
  started with the other value would return stats presence that contradicts the
  request.
- A list must hash its query parameters (`QueryParamHash`) into the ID, so two
  different filters never coalesce.
- A create must never coalesce at all, so `CreateTaskRun` uses a fresh UUID
  (`flow-grpc-task-run-create-{uuid}`) and `USE_EXISTING` can never match.

Prefix deterministic IDs with the transport (`flow-grpc-`). A deterministic ID
plus `USE_EXISTING` attaches to whatever execution already holds that name, so
an ID shared with a different workflow type — a bespoke predecessor still
running during a rollout, for instance — yields a result payload this proxy
cannot decode.

## Timeout Ladder

The ladder is bounded from the outside, not chosen from the on-site budget:
`server.WriteTimeout` is a deadline on the response write, so a handler that
answers later than that cannot deliver its answer. Keep
`ActivityStartToCloseTimeout` < `grpcproxy.WorkflowExecutionTimeout` <
`cutil.WorkflowContextTimeout` < `server.WriteTimeout`, currently
40s < 45s < 50s < 60s. `Test_ProxyTimeoutsFitWriteTimeout` in
`api/internal/server` guards the outer bound. Raising the on-site budget means
raising the server and load-balancer timeouts first.

## Before Coding

Confirm these details before editing:

- REST operation path, method, auth role, org/site scoping, Flow enablement
  check, request model, response model, and expected status code.
- Target Flow method, usually `/v1.Flow/<Method>`, and whether it is unary.
  The proxy does not support streaming methods.
- Typed protobuf request and optional typed protobuf response.
- Workflow ID derivation and conflict policy for this call.
- Secret fields that must not appear in Temporal history (top-level protojson
  field names).
- Whether timeout should terminate the workflow (`TerminateWorkflowOnTimeOut`)
  when `ExecuteFlowGRPC` returns `504`, which is what the bespoke TaskRun
  workflows do today.

## Implementation Workflow

1. Keep auth, tenant/org membership, site lookup, Flow enablement, role checks,
   request validation, and REST semantics in the REST handler.
2. Build the typed Flow protobuf request before calling the proxy.
3. Call `common.ExecuteFlowGRPC(ctx, siteTemporalClient, fullMethod, reqProto,
   respProtoOrNil, workflowID, conflictPolicy, siteIDSecretKey, secretFields...)`.
   Passing `secretFields` requires a non-empty `siteIDSecretKey`; the helper
   rejects the combination rather than send the fields unredacted.
4. On `StatusGatewayTimeout`, call `TerminateWorkflowOnTimeOut` with the same
   `workflowID` when matching existing TaskRun UX.
5. Return a curated REST response. Do not expose Flow protobufs or secret
   fields directly unless the API contract already does.
6. For a new public REST endpoint, register the route and update OpenAPI. For a
   migration from a bespoke workflow to the generic proxy, keep the REST
   contract and the parameter-derivation rules for the workflow ID unchanged,
   but namespace the resulting ID by transport as described above. The derived
   ID string itself must change, otherwise the proxy and the workflow it
   replaces can attach to each other.

## Rollout Requirement

A workflow type is known only to the workers that registered it. The cloud API
and each site's agent ship as separate Helm releases (`nico-rest` and
`nico-rest-site-agent`) and cannot be upgraded atomically, and Temporal accepts
a submission for a type no worker knows: the execution is created, no worker can
advance it, and the caller sees only a timeout after
`grpcproxy.WorkflowExecutionTimeout`.

So a handler may not start dispatching through `InvokeFlowGRPC` in the same
release that first registers it on the site agent. Register the proxy first,
wait for every site to run that agent, and switch handlers in a later release.
Retire the workflow a migration replaces in a third release, once no supported
cloud release still submits it.

No handler dispatches through `ExecuteFlowGRPC` yet;
`rest-api/api/pkg/api/handler/taskrun.go` is the first migration and still uses
its per-method workflows.
