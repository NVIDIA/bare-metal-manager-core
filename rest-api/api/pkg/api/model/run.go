// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
)

// A Run is the REST representation of Flow's operation run: a phased,
// policy-gated execution of one operation across many racks. Each run
// materializes a set of per-rack targets (APIRunTarget), and each target
// drives at most one Task. Callers drill into execution detail via the Task
// endpoints using APIRunTarget.TaskID.

// ~~~~~ Status enums ~~~~~ //

var protoToAPIRunStatus = map[flowv1.OperationRunStatus]string{
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN:                 "Unknown",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PENDING:                 "Pending",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_RUNNING:                 "Running",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PAUSED:                  "Paused",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED:               "Completed",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_CANCELLED:               "Cancelled",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_FAILED:                  "Failed",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED_WITH_FAILURES: "CompletedWithFailures",
}

// validRunStatuses lists the run statuses accepted as a list filter.
// UNKNOWN is intentionally excluded (it is not a filterable state).
var validRunStatuses = []string{
	"Pending", "Running", "Paused", "Completed", "Cancelled", "Failed", "CompletedWithFailures",
}

var validRunStatusesAny = func() []any {
	out := make([]any, len(validRunStatuses))
	for i, s := range validRunStatuses {
		out[i] = s
	}
	return out
}()

// apiToProtoRunStatus is the reverse of protoToAPIRunStatus for the
// filterable statuses.
var apiToProtoRunStatus = func() map[string]flowv1.OperationRunStatus {
	out := make(map[string]flowv1.OperationRunStatus, len(protoToAPIRunStatus))
	for proto, api := range protoToAPIRunStatus {
		if proto == flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN {
			continue
		}
		out[api] = proto
	}
	return out
}()

var protoToAPIRunStatusReason = map[flowv1.OperationRunStatusReason]string{
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_UNKNOWN:                "Unknown",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_NONE:                   "None",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_OPERATOR_PAUSED:        "OperatorPaused",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_PHASE_GATE:             "PhaseGate",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_SAFETY_GATE:            "SafetyGate",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_CONFLICT_RETRY_TIMEOUT: "ConflictRetryTimeout",
}

// APIRunTargetStatus enumerates per-rack target execution states.
type APIRunTargetStatus string

const (
	APIRunTargetStatusUnknown    APIRunTargetStatus = "Unknown"
	APIRunTargetStatusPending    APIRunTargetStatus = "Pending"
	APIRunTargetStatusBlocked    APIRunTargetStatus = "Blocked"
	APIRunTargetStatusSubmitted  APIRunTargetStatus = "Submitted"
	APIRunTargetStatusCompleted  APIRunTargetStatus = "Completed"
	APIRunTargetStatusFailed     APIRunTargetStatus = "Failed"
	APIRunTargetStatusTerminated APIRunTargetStatus = "Terminated"
	APIRunTargetStatusSkipped    APIRunTargetStatus = "Skipped"
	APIRunTargetStatusClaimed    APIRunTargetStatus = "Claimed"
)

var validRunTargetStatuses = []APIRunTargetStatus{
	APIRunTargetStatusPending,
	APIRunTargetStatusBlocked,
	APIRunTargetStatusSubmitted,
	APIRunTargetStatusCompleted,
	APIRunTargetStatusFailed,
	APIRunTargetStatusTerminated,
	APIRunTargetStatusSkipped,
	APIRunTargetStatusClaimed,
}

var validRunTargetStatusesAny = func() []any {
	out := make([]any, len(validRunTargetStatuses))
	for i, s := range validRunTargetStatuses {
		out[i] = s
	}
	return out
}()

var protoToAPIRunTargetStatus = map[flowv1.OperationRunTargetStatus]APIRunTargetStatus{
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN:    APIRunTargetStatusUnknown,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_PENDING:    APIRunTargetStatusPending,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_BLOCKED:    APIRunTargetStatusBlocked,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SUBMITTED:  APIRunTargetStatusSubmitted,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_COMPLETED:  APIRunTargetStatusCompleted,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_FAILED:     APIRunTargetStatusFailed,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_TERMINATED: APIRunTargetStatusTerminated,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SKIPPED:    APIRunTargetStatusSkipped,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_CLAIMED:    APIRunTargetStatusClaimed,
}

var apiToProtoRunTargetStatus = func() map[APIRunTargetStatus]flowv1.OperationRunTargetStatus {
	out := make(map[APIRunTargetStatus]flowv1.OperationRunTargetStatus, len(protoToAPIRunTargetStatus))
	for k, v := range protoToAPIRunTargetStatus {
		out[v] = k
	}
	return out
}()

// ~~~~~ Response model ~~~~~ //

// APIRun is the API response model for a Flow operation run. List
// responses populate the summary fields only; get responses additionally
// populate Stats when the caller requests derived stats.
type APIRun struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	OperationType APIOperationType `json:"operationType"`
	OperationCode string           `json:"operationCode"`
	Status        string           `json:"status"`
	// StatusReason explains why a run is paused or terminal (e.g. PhaseGate,
	// SafetyGate). "None" when there is no qualifying reason.
	StatusReason  string     `json:"statusReason"`
	StatusMessage string     `json:"statusMessage"`
	TotalPhases   int32      `json:"totalPhases"`
	Created       time.Time  `json:"created"`
	Updated       time.Time  `json:"updated"`
	Started       *time.Time `json:"started"`
	Finished      *time.Time `json:"finished"`
	// Stats is present only when the caller requests derived stats on a get.
	Stats *APIRunStats `json:"stats,omitempty"`
}

// APIRunStats summarizes target outcomes for the active phase and for all
// phases processed so far.
type APIRunStats struct {
	CurrentPhase    APIRunPhaseStats `json:"currentPhase"`
	CumulativePhase APIRunPhaseStats `json:"cumulativePhase"`
}

// APIRunPhaseStats summarizes target outcomes for one phase scope.
type APIRunPhaseStats struct {
	PhaseIndex      int32               `json:"phaseIndex"`
	SelectedTargets int32               `json:"selectedTargets"`
	OutcomeCounts   APIRunOutcomeCounts `json:"outcomeCounts"`
}

// APIRunOutcomeCounts counts terminal target outcomes within a phase scope.
type APIRunOutcomeCounts struct {
	Completed  int32 `json:"completed"`
	Failed     int32 `json:"failed"`
	Terminated int32 `json:"terminated"`
	Skipped    int32 `json:"skipped"`
}

// FromProtoSummary populates the summary fields shared by list and get
// responses from an OperationRunSummary.
func (a *APIRun) FromProtoSummary(s *flowv1.OperationRunSummary) {
	if s == nil {
		return
	}
	if s.GetId() != nil {
		a.ID = s.GetId().GetId()
	}
	a.Name = s.GetName()
	a.Description = s.GetDescription()
	if k := s.GetOperationKind(); k != nil {
		a.OperationType = enumOr(protoToAPIOperationType, k.GetType(), "")
		a.OperationCode = k.GetCode()
	}
	if st := s.GetState(); st != nil {
		a.Status = enumOr(protoToAPIRunStatus, st.GetStatus(), "Unknown")
		a.StatusReason = enumOr(protoToAPIRunStatusReason, st.GetReason(), "Unknown")
	}
	a.StatusMessage = s.GetStatusMessage()
	a.TotalPhases = s.GetTotalPhases()
	if ts := s.GetCreatedAt(); ts != nil {
		a.Created = ts.AsTime().UTC()
	}
	if ts := s.GetUpdatedAt(); ts != nil {
		a.Updated = ts.AsTime().UTC()
	}
	if ts := s.GetStartedAt(); ts != nil {
		v := ts.AsTime().UTC()
		a.Started = &v
	}
	if ts := s.GetFinishedAt(); ts != nil {
		v := ts.AsTime().UTC()
		a.Finished = &v
	}
}

// FromProto populates an APIRun from a full OperationRun, including
// derived stats when Flow computed them.
func (a *APIRun) FromProto(run *flowv1.OperationRun) {
	if run == nil {
		return
	}
	a.FromProtoSummary(run.GetSummary())
	if stats := run.GetStats(); stats != nil {
		a.Stats = newAPIRunStats(stats)
	}
}

func newAPIRunStats(s *flowv1.OperationRunStats) *APIRunStats {
	if s == nil {
		return nil
	}
	return &APIRunStats{
		CurrentPhase:    phaseStatsFromProto(s.GetCurrentPhaseStats()),
		CumulativePhase: phaseStatsFromProto(s.GetCumulativePhaseStats()),
	}
}

func phaseStatsFromProto(p *flowv1.OperationRunPhaseStats) APIRunPhaseStats {
	out := APIRunPhaseStats{}
	if p == nil {
		return out
	}
	out.PhaseIndex = p.GetPhaseIndex()
	out.SelectedTargets = p.GetSelectedTargets()
	if c := p.GetOutcomeCounts(); c != nil {
		out.OutcomeCounts = APIRunOutcomeCounts{
			Completed:  c.GetCompleted(),
			Failed:     c.GetFailed(),
			Terminated: c.GetTerminated(),
			Skipped:    c.GetSkipped(),
		}
	}
	return out
}

// NewAPIRunFromProto builds an APIRun from a full OperationRun.
func NewAPIRunFromProto(run *flowv1.OperationRun) *APIRun {
	a := &APIRun{}
	a.FromProto(run)
	return a
}

// NewAPIRunFromSummary builds an APIRun from an OperationRunSummary.
func NewAPIRunFromSummary(s *flowv1.OperationRunSummary) *APIRun {
	a := &APIRun{}
	a.FromProtoSummary(s)
	return a
}

// ~~~~~ Target response model ~~~~~ //

// APIRunTarget is the API response model for one materialized rack
// execution target of a run. TaskID references the Task the run
// submitted for this rack (nil until submission); clients drill into execution
// detail via GET /task/{taskId}.
type APIRunTarget struct {
	ID            string             `json:"id"`
	RunID         string             `json:"runId"`
	RackID        string             `json:"rackId"`
	SequenceIndex int32              `json:"sequenceIndex"`
	PhaseIndex    int32              `json:"phaseIndex"`
	TaskID        *string            `json:"taskId"`
	Status        APIRunTargetStatus `json:"status"`
	Message       string             `json:"message"`
	Created       time.Time          `json:"created"`
	Updated       time.Time          `json:"updated"`
}

// FromProto populates an APIRunTarget from an OperationRunTarget.
func (t *APIRunTarget) FromProto(p *flowv1.OperationRunTarget) {
	if p == nil {
		return
	}
	if p.GetId() != nil {
		t.ID = p.GetId().GetId()
	}
	if p.GetOperationRunId() != nil {
		t.RunID = p.GetOperationRunId().GetId()
	}
	if p.GetRackId() != nil {
		t.RackID = p.GetRackId().GetId()
	}
	t.SequenceIndex = p.GetSequenceIndex()
	t.PhaseIndex = p.GetPhaseIndex()
	if id := p.GetTaskId(); id != nil && id.GetId() != "" {
		v := id.GetId()
		t.TaskID = &v
	}
	t.Status = enumOr(protoToAPIRunTargetStatus, p.GetStatus(), APIRunTargetStatusUnknown)
	t.Message = p.GetMessage()
	if ts := p.GetCreatedAt(); ts != nil {
		t.Created = ts.AsTime().UTC()
	}
	if ts := p.GetUpdatedAt(); ts != nil {
		t.Updated = ts.AsTime().UTC()
	}
}

// NewAPIRunTarget builds an APIRunTarget from an OperationRunTarget.
func NewAPIRunTarget(p *flowv1.OperationRunTarget) *APIRunTarget {
	t := &APIRunTarget{}
	t.FromProto(p)
	return t
}

// ~~~~~ Get (siteId + includeStats via query) ~~~~~ //

// APIRunGetRequest captures query parameters for GET /run/{id}.
type APIRunGetRequest struct {
	SiteID       string `query:"siteId"`
	IncludeStats bool   `query:"includeStats"`
}

func (r *APIRunGetRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
	)
}

// ~~~~~ List ~~~~~ //

// APIRunGetAllRequest binds query parameters for GET /run. Pagination
// is bound separately via pagination.PageRequest.
type APIRunGetAllRequest struct {
	SiteID        string           `query:"siteId"`
	Status        string           `query:"status"`
	OperationType APIOperationType `query:"operationType"`
}

func (r *APIRunGetAllRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.OperationType,
			validation.When(r.OperationType != "",
				validation.In(validOperationTypesAny...).Error(
					fmt.Sprintf("operationType must be one of %v", validOperationTypes)))),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validRunStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validRunStatuses)))),
	)
}

// ToProto converts the list filters into the Flow ListOperationRunsRequest.
func (r *APIRunGetAllRequest) ToProto(page pagination.PageRequest) (*flowv1.ListOperationRunsRequest, error) {
	req := &flowv1.ListOperationRunsRequest{}
	filter := &flowv1.OperationRunFilter{}
	hasFilter := false

	if r.Status != "" {
		status, ok := apiToProtoRunStatus[r.Status]
		if !ok {
			return nil, fmt.Errorf("invalid status %q (expected one of %v)", r.Status, validRunStatuses)
		}
		filter.States = []*flowv1.OperationRunStateFilter{{Status: &status}}
		hasFilter = true
	}
	if r.OperationType != "" {
		opType, err := r.OperationType.ToProto()
		if err != nil {
			return nil, err
		}
		filter.OperationKinds = []*flowv1.OperationKind{{Type: opType}}
		hasFilter = true
	}
	if hasFilter {
		req.Filter = filter
	}

	if page.PageSize != nil && page.PageNumber != nil && *page.PageSize > 0 && *page.PageNumber > 0 {
		req.Pagination = &flowv1.Pagination{
			Offset: int32((*page.PageNumber - 1) * (*page.PageSize)),
			Limit:  int32(*page.PageSize),
		}
	}
	return req, nil
}

// QueryValues returns the request fields that feed the workflow ID hash,
// including pagination so different pages map to distinct workflow IDs.
func (r *APIRunGetAllRequest) QueryValues(page pagination.PageRequest) url.Values {
	v := url.Values{}
	v.Set("siteId", r.SiteID)
	if r.Status != "" {
		v.Set("status", r.Status)
	}
	if r.OperationType != "" {
		v.Set("operationType", string(r.OperationType))
	}
	if page.PageNumber != nil && *page.PageNumber != 0 {
		v.Set("pageNumber", strconv.Itoa(*page.PageNumber))
	}
	if page.PageSize != nil && *page.PageSize != 0 {
		v.Set("pageSize", strconv.Itoa(*page.PageSize))
	}
	return v
}

// ~~~~~ List targets ~~~~~ //

// APIRunTargetGetAllRequest binds query parameters for
// GET /run/{id}/target.
type APIRunTargetGetAllRequest struct {
	SiteID     string             `query:"siteId"`
	Status     APIRunTargetStatus `query:"status"`
	PhaseScope string             `query:"phaseScope"`
}

var validRunPhaseScopes = []string{"currentPhase", "completedPhases", "currentAndCompletedPhases"}

var validRunPhaseScopesAny = func() []any {
	out := make([]any, len(validRunPhaseScopes))
	for i, s := range validRunPhaseScopes {
		out[i] = s
	}
	return out
}()

var apiToProtoRunPhaseScope = map[string]flowv1.OperationRunTargetPhaseScope{
	"":                          flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_PHASE,
	"currentPhase":              flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_PHASE,
	"completedPhases":           flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_COMPLETED_PHASES,
	"currentAndCompletedPhases": flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_AND_COMPLETED_PHASES,
}

func (r *APIRunTargetGetAllRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validRunTargetStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validRunTargetStatuses)))),
		validation.Field(&r.PhaseScope,
			validation.When(r.PhaseScope != "",
				validation.In(validRunPhaseScopesAny...).Error(
					fmt.Sprintf("phaseScope must be one of %v", validRunPhaseScopes)))),
	)
}

// ToProto converts the target-list filters into the Flow
// ListOperationRunTargetsRequest. status UNKNOWN means no status filter.
func (r *APIRunTargetGetAllRequest) ToProto(runID string, page pagination.PageRequest) *flowv1.ListOperationRunTargetsRequest {
	req := &flowv1.ListOperationRunTargetsRequest{
		OperationRunId: &flowv1.UUID{Id: runID},
		Status:         flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN,
		PhaseScope:     apiToProtoRunPhaseScope[r.PhaseScope],
	}
	if r.Status != "" {
		if s, ok := apiToProtoRunTargetStatus[r.Status]; ok {
			req.Status = s
		}
	}
	if page.PageSize != nil && page.PageNumber != nil && *page.PageSize > 0 && *page.PageNumber > 0 {
		req.Pagination = &flowv1.Pagination{
			Offset: int32((*page.PageNumber - 1) * (*page.PageSize)),
			Limit:  int32(*page.PageSize),
		}
	}
	return req
}

// QueryValues returns the fields that feed the workflow ID hash for the
// target-list endpoint, including pagination.
func (r *APIRunTargetGetAllRequest) QueryValues(page pagination.PageRequest) url.Values {
	v := url.Values{}
	v.Set("siteId", r.SiteID)
	if r.Status != "" {
		v.Set("status", string(r.Status))
	}
	if r.PhaseScope != "" {
		v.Set("phaseScope", r.PhaseScope)
	}
	if page.PageNumber != nil && *page.PageNumber != 0 {
		v.Set("pageNumber", strconv.Itoa(*page.PageNumber))
	}
	if page.PageSize != nil && *page.PageSize != 0 {
		v.Set("pageSize", strconv.Itoa(*page.PageSize))
	}
	return v
}

// ~~~~~ Lifecycle request bodies (siteId in body) ~~~~~ //

// APIRunSiteRequest is the shared JSON body for the pause/resume/advance
// lifecycle actions, which need only the target Site.
type APIRunSiteRequest struct {
	SiteID string `json:"siteId"`
}

func (r *APIRunSiteRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APIRunAdvanceRequest is the JSON body for POST /run/{id}/advance.
// ExpectedPhaseIndex is an optional guard: when set, the phase that would be
// opened must match, otherwise Flow rejects the advance.
type APIRunAdvanceRequest struct {
	SiteID             string `json:"siteId"`
	ExpectedPhaseIndex *int32 `json:"expectedPhaseIndex"`
}

func (r *APIRunAdvanceRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APIRunCancelRequest is the JSON body for POST /run/{id}/cancel.
type APIRunCancelRequest struct {
	SiteID string `json:"siteId"`
	Reason string `json:"reason"`
}

func (r *APIRunCancelRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// ~~~~~ Create ~~~~~ //

// safety-gate scope maps between the API string and Flow's enum. The empty
// value maps to the current-phase default.
var validRunGateScopes = []string{"currentPhase", "cumulativeRun"}

var validRunGateScopesAny = func() []any {
	out := make([]any, len(validRunGateScopes))
	for i, s := range validRunGateScopes {
		out[i] = s
	}
	return out
}()

var apiToProtoGateScope = map[string]flowv1.OperationRunSafetyGateScope{
	"":              flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"currentPhase":  flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"cumulativeRun": flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CUMULATIVE_RUN,
}

// APIRunCreateRequest is the JSON body for POST /run. A run executes
// exactly one operation (currently firmware) across a candidate set of racks,
// narrowed by an optional selector and divided into phases by an optional phase
// policy. operationType is inferred from the operation and is not accepted here.
type APIRunCreateRequest struct {
	SiteID      string `json:"siteId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Selector narrows the candidate racks. Omit to target the full candidate
	// scope (100%).
	Selector  *APIRunSelector `json:"selector"`
	Options   APIRunOptions   `json:"options"`
	Operation APIRunOperation `json:"operation"`
}

// APIRunSelector selects a subset of candidate racks. Percentage is the
// only supported selector today.
type APIRunSelector struct {
	Percentage *APIRunPercentageSelector `json:"percentage"`
}

// APIRunPercentageSelector selects a percentage of the candidate racks.
// Seed is optional; when omitted Flow generates and stores one so the cohort
// is deterministic and auditable.
type APIRunPercentageSelector struct {
	Percent int32  `json:"percent"`
	Seed    string `json:"seed"`
}

// APIRunOptions configures execution policy for the run.
type APIRunOptions struct {
	// MaxConcurrentTargets caps how many targets may have active child tasks at
	// once. Required, must be greater than zero.
	MaxConcurrentTargets int32                 `json:"maxConcurrentTargets"`
	SafetyPolicy         *APIRunSafetyPolicy   `json:"safetyPolicy"`
	ConflictPolicy       *APIRunConflictPolicy `json:"conflictPolicy"`
	OrderingPolicy       *APIRunOrderingPolicy `json:"orderingPolicy"`
	PhasePolicy          *APIRunPhasePolicy    `json:"phasePolicy"`
}

// APIRunSafetyPolicy is a set of gates that pause the run when any
// one of them trips (OR composition).
type APIRunSafetyPolicy struct {
	Gates []APIRunSafetyGate `json:"gates"`
}

// APIRunSafetyGate is exactly one of failureRate or failureCount.
type APIRunSafetyGate struct {
	FailureRate  *APIRunFailureRateGate  `json:"failureRate"`
	FailureCount *APIRunFailureCountGate `json:"failureCount"`
}

// APIRunFailureRateGate pauses when failed/planned reaches ThresholdPercent
// for the scope.
type APIRunFailureRateGate struct {
	Scope            string `json:"scope"`
	ThresholdPercent int32  `json:"thresholdPercent"`
}

// APIRunFailureCountGate pauses when failed targets reach ThresholdCount
// for the scope.
type APIRunFailureCountGate struct {
	Scope          string `json:"scope"`
	ThresholdCount int32  `json:"thresholdCount"`
}

// APIRunConflictPolicy configures how blocked targets are retried. Retry
// is the only supported strategy today.
type APIRunConflictPolicy struct {
	Retry *APIRunConflictRetry `json:"retry"`
}

// APIRunConflictRetry configures retry backoff for blocked targets.
// Durations are Go duration strings (e.g. "30m", "10s"); empty means "use the
// operation default".
type APIRunConflictRetry struct {
	RetryTimeout      string `json:"retryTimeout"`
	InitialRetryDelay string `json:"initialRetryDelay"`
	MaxRetryDelay     string `json:"maxRetryDelay"`
}

// APIRunOrderingPolicy controls the order in which targets are processed.
// Random is the only supported ordering today.
type APIRunOrderingPolicy struct {
	Random *APIRunRandomOrdering `json:"random"`
}

// APIRunRandomOrdering orders targets randomly. Seed is optional; Flow
// generates and stores one when omitted.
type APIRunRandomOrdering struct {
	Seed string `json:"seed"`
}

// APIRunPhasePolicy divides the selected targets into phases. Exactly one
// of equal, percentage, or count may be set; omit the whole policy for a single
// phase covering all targets.
type APIRunPhasePolicy struct {
	Equal      *APIRunEqualPhases      `json:"equal"`
	Percentage *APIRunPercentagePhases `json:"percentage"`
	Count      *APIRunCountPhases      `json:"count"`
	// AutoAdvance, when true, advances phases automatically as long as safety
	// gates are not tripped. When false (default) each completed phase pauses at
	// a phase gate until advanced explicitly.
	AutoAdvance bool `json:"autoAdvance"`
}

// APIRunEqualPhases splits targets into PhaseCount roughly equal phases.
type APIRunEqualPhases struct {
	PhaseCount int32 `json:"phaseCount"`
}

// APIRunPercentagePhases splits targets by percentage. Values must sum to
// 100.
type APIRunPercentagePhases struct {
	Phases []int32 `json:"phases"`
}

// APIRunCountPhases splits targets by explicit counts. A generated final
// phase covers any remaining targets.
type APIRunCountPhases struct {
	Phases []int32 `json:"phases"`
}

// APIRunOperation is the operation the run executes. Firmware is the only
// supported operation today.
type APIRunOperation struct {
	Firmware *APIRunFirmwareOperation `json:"firmware"`
	// ExcludeRunIDs excludes racks materialized by prior runs from
	// this run's candidate scope.
	ExcludeRunIDs []string `json:"excludeRunIds"`
}

// APIRunFirmwareOperation configures a firmware rollout.
type APIRunFirmwareOperation struct {
	Version                string   `json:"version"`
	RuleID                 *string  `json:"ruleId"`
	OverrideReadinessCheck bool     `json:"overrideReadinessCheck"`
	SubTargets             []string `json:"subTargets"`
}

// Validate enforces request shape only; Flow performs semantic validation
// (selector ranges, phase math, operation code membership) server-side.
func (r *APIRunCreateRequest) Validate() error {
	if err := validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.Name, validation.Required.Error("name is required")),
	); err != nil {
		return err
	}
	if r.Options.MaxConcurrentTargets <= 0 {
		return fmt.Errorf("options.maxConcurrentTargets must be greater than zero")
	}
	if r.Operation.Firmware == nil {
		return fmt.Errorf("operation.firmware is required")
	}
	if r.Operation.Firmware.Version == "" {
		return fmt.Errorf("operation.firmware.version is required")
	}
	for i, g := range gatesOf(r.Options.SafetyPolicy) {
		if (g.FailureRate == nil) == (g.FailureCount == nil) {
			return fmt.Errorf("options.safetyPolicy.gates[%d] must set exactly one of failureRate or failureCount", i)
		}
		scope := g.scope()
		if _, ok := apiToProtoGateScope[scope]; !ok {
			return fmt.Errorf("options.safetyPolicy.gates[%d].scope must be one of %v", i, validRunGateScopes)
		}
	}
	if p := r.Options.PhasePolicy; p != nil {
		set := 0
		if p.Equal != nil {
			set++
		}
		if p.Percentage != nil {
			set++
		}
		if p.Count != nil {
			set++
		}
		if set > 1 {
			return fmt.Errorf("options.phasePolicy must set at most one of equal, percentage, count")
		}
	}
	return nil
}

func gatesOf(p *APIRunSafetyPolicy) []APIRunSafetyGate {
	if p == nil {
		return nil
	}
	return p.Gates
}

func (g APIRunSafetyGate) scope() string {
	if g.FailureRate != nil {
		return g.FailureRate.Scope
	}
	if g.FailureCount != nil {
		return g.FailureCount.Scope
	}
	return ""
}

// ToProto converts the create request into the Flow CreateOperationRunRequest.
func (r *APIRunCreateRequest) ToProto() (*flowv1.CreateOperationRunRequest, error) {
	cfg := &flowv1.OperationRunConfiguration{}

	if r.Selector != nil && r.Selector.Percentage != nil {
		cfg.Selector = &flowv1.OperationRunSelector{
			Selector: &flowv1.OperationRunSelector_Percentage{
				Percentage: &flowv1.PercentageSelector{
					Percentage: r.Selector.Percentage.Percent,
					Seed:       r.Selector.Percentage.Seed,
				},
			},
		}
	}

	opts, err := r.Options.toProto()
	if err != nil {
		return nil, err
	}
	cfg.Options = opts

	op, err := r.Operation.toProto()
	if err != nil {
		return nil, err
	}
	cfg.Operation = op

	return &flowv1.CreateOperationRunRequest{
		Name:          r.Name,
		Description:   r.Description,
		Configuration: cfg,
	}, nil
}

func (o APIRunOptions) toProto() (*flowv1.OperationRunOptions, error) {
	out := &flowv1.OperationRunOptions{
		MaxConcurrentTargets: o.MaxConcurrentTargets,
	}

	if o.SafetyPolicy != nil {
		gates := make([]*flowv1.OperationRunSafetyGate, 0, len(o.SafetyPolicy.Gates))
		for _, g := range o.SafetyPolicy.Gates {
			gates = append(gates, g.toProto())
		}
		out.SafetyPolicy = &flowv1.OperationRunSafetyPolicy{Gates: gates}
	}

	if o.ConflictPolicy != nil && o.ConflictPolicy.Retry != nil {
		retry, err := o.ConflictPolicy.Retry.toProto()
		if err != nil {
			return nil, err
		}
		out.ConflictPolicy = &flowv1.OperationRunConflictPolicy{
			Strategy: &flowv1.OperationRunConflictPolicy_Retry{Retry: retry},
		}
	}

	if o.OrderingPolicy != nil && o.OrderingPolicy.Random != nil {
		out.OrderingPolicy = &flowv1.OperationRunOrderingPolicy{
			Ordering: &flowv1.OperationRunOrderingPolicy_Random{
				Random: &flowv1.OperationRunRandomOrdering{Seed: o.OrderingPolicy.Random.Seed},
			},
		}
	}

	if o.PhasePolicy != nil {
		out.PhasePolicy = o.PhasePolicy.toProto()
	}

	return out, nil
}

func (g APIRunSafetyGate) toProto() *flowv1.OperationRunSafetyGate {
	if g.FailureRate != nil {
		return &flowv1.OperationRunSafetyGate{
			Gate: &flowv1.OperationRunSafetyGate_FailureRate{
				FailureRate: &flowv1.OperationRunFailureRateGate{
					Scope:                   apiToProtoGateScope[g.FailureRate.Scope],
					FailureThresholdPercent: g.FailureRate.ThresholdPercent,
				},
			},
		}
	}
	return &flowv1.OperationRunSafetyGate{
		Gate: &flowv1.OperationRunSafetyGate_FailureCount{
			FailureCount: &flowv1.OperationRunFailureCountGate{
				Scope:                 apiToProtoGateScope[g.FailureCount.Scope],
				FailureThresholdCount: g.FailureCount.ThresholdCount,
			},
		},
	}
}

func (r APIRunConflictRetry) toProto() (*flowv1.OperationRunConflictRetryPolicy, error) {
	timeout, err := optionalDurationToProto(r.RetryTimeout)
	if err != nil {
		return nil, fmt.Errorf("options.conflictPolicy.retry.retryTimeout: %w", err)
	}
	initial, err := optionalDurationToProto(r.InitialRetryDelay)
	if err != nil {
		return nil, fmt.Errorf("options.conflictPolicy.retry.initialRetryDelay: %w", err)
	}
	maxDelay, err := optionalDurationToProto(r.MaxRetryDelay)
	if err != nil {
		return nil, fmt.Errorf("options.conflictPolicy.retry.maxRetryDelay: %w", err)
	}
	return &flowv1.OperationRunConflictRetryPolicy{
		RetryTimeout:      timeout,
		InitialRetryDelay: initial,
		MaxRetryDelay:     maxDelay,
	}, nil
}

func (p APIRunPhasePolicy) toProto() *flowv1.OperationRunPhasePolicy {
	out := &flowv1.OperationRunPhasePolicy{
		AdvancePolicy: &flowv1.OperationRunPhaseAdvancePolicy{AutoAdvance: p.AutoAdvance},
	}
	switch {
	case p.Equal != nil:
		out.Plan = &flowv1.OperationRunPhasePolicy_Equal{
			Equal: &flowv1.EqualOperationRunPhases{PhaseCount: p.Equal.PhaseCount},
		}
	case p.Percentage != nil:
		phases := make([]*flowv1.OperationRunPercentagePhase, 0, len(p.Percentage.Phases))
		for _, pct := range p.Percentage.Phases {
			phases = append(phases, &flowv1.OperationRunPercentagePhase{Percentage: pct})
		}
		out.Plan = &flowv1.OperationRunPhasePolicy_Percentage{
			Percentage: &flowv1.PercentageOperationRunPhases{Phases: phases},
		}
	case p.Count != nil:
		phases := make([]*flowv1.OperationRunCountPhase, 0, len(p.Count.Phases))
		for _, n := range p.Count.Phases {
			phases = append(phases, &flowv1.OperationRunCountPhase{Count: n})
		}
		out.Plan = &flowv1.OperationRunPhasePolicy_Count{
			Count: &flowv1.CountOperationRunPhases{Phases: phases},
		}
	}
	return out
}

func (o APIRunOperation) toProto() (*flowv1.OperationRunOperation, error) {
	if o.Firmware == nil {
		return nil, fmt.Errorf("operation.firmware is required")
	}
	fw := &flowv1.UpgradeFirmwareRequest{
		TargetVersion:          &o.Firmware.Version,
		SubTargets:             o.Firmware.SubTargets,
		OverrideReadinessCheck: o.Firmware.OverrideReadinessCheck,
	}
	if o.Firmware.RuleID != nil && *o.Firmware.RuleID != "" {
		fw.RuleId = &flowv1.UUID{Id: *o.Firmware.RuleID}
	}

	out := &flowv1.OperationRunOperation{
		Operation: &flowv1.OperationRunOperation_UpgradeFirmware{UpgradeFirmware: fw},
	}

	if len(o.ExcludeRunIDs) > 0 {
		excludes := make([]*flowv1.UUID, 0, len(o.ExcludeRunIDs))
		for _, id := range o.ExcludeRunIDs {
			excludes = append(excludes, &flowv1.UUID{Id: id})
		}
		out.TargetScope = &flowv1.OperationRunTargetScope{ExcludeOperationRunIds: excludes}
	}

	return out, nil
}

// optionalDurationToProto parses a Go duration string into a protobuf Duration.
// An empty string returns nil so Flow falls back to the operation default.
func optionalDurationToProto(s string) (*durationpb.Duration, error) {
	if s == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return durationpb.New(d), nil
}
