// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
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
// materializes a set of per-rack targets (APITaskRunTarget), and each target
// drives at most one Task. Callers drill into execution detail via the Task
// endpoints using APITaskRunTarget.TaskID.

// ~~~~~ Status enums ~~~~~ //

// TaskRunStatus enumerates the lifecycle states of a task run.
type TaskRunStatus string

const (
	TaskRunStatusUnknown               TaskRunStatus = "Unknown"
	TaskRunStatusPending               TaskRunStatus = "Pending"
	TaskRunStatusRunning               TaskRunStatus = "Running"
	TaskRunStatusPaused                TaskRunStatus = "Paused"
	TaskRunStatusCompleted             TaskRunStatus = "Completed"
	TaskRunStatusCancelled             TaskRunStatus = "Cancelled"
	TaskRunStatusFailed                TaskRunStatus = "Failed"
	TaskRunStatusCompletedWithFailures TaskRunStatus = "CompletedWithFailures"
)

var taskRunStatusChoiceMap = map[TaskRunStatus]flowv1.OperationRunStatus{
	TaskRunStatusUnknown:               flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN,
	TaskRunStatusPending:               flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PENDING,
	TaskRunStatusRunning:               flowv1.OperationRunStatus_OPERATION_RUN_STATUS_RUNNING,
	TaskRunStatusPaused:                flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PAUSED,
	TaskRunStatusCompleted:             flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED,
	TaskRunStatusCancelled:             flowv1.OperationRunStatus_OPERATION_RUN_STATUS_CANCELLED,
	TaskRunStatusFailed:                flowv1.OperationRunStatus_OPERATION_RUN_STATUS_FAILED,
	TaskRunStatusCompletedWithFailures: flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED_WITH_FAILURES,
}

// validTaskRunStatuses lists the run statuses accepted as a list filter.
// Unknown is intentionally excluded (it is not a filterable state).
var validTaskRunStatuses = []TaskRunStatus{
	TaskRunStatusPending,
	TaskRunStatusRunning,
	TaskRunStatusPaused,
	TaskRunStatusCompleted,
	TaskRunStatusCancelled,
	TaskRunStatusFailed,
	TaskRunStatusCompletedWithFailures,
}

var validTaskRunStatusesAny = func() []any {
	out := make([]any, len(validTaskRunStatuses))
	for i, s := range validTaskRunStatuses {
		out[i] = s
	}
	return out
}()

// ToProto converts the REST run status to its Flow enum value.
func (s TaskRunStatus) ToProto() flowv1.OperationRunStatus {
	if v, ok := taskRunStatusChoiceMap[s]; ok {
		return v
	}
	return flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN
}

// FromProto populates the REST run status from a Flow enum value.
func (s *TaskRunStatus) FromProto(p flowv1.OperationRunStatus) {
	if s == nil {
		return
	}
	for rest, proto := range taskRunStatusChoiceMap {
		if proto == p {
			*s = rest
			return
		}
	}
	*s = TaskRunStatusUnknown
}

// TaskRunStatusReason explains why a run is paused or terminal. It is
// response-only, so it converts from Flow but never back.
type TaskRunStatusReason string

const (
	TaskRunStatusReasonUnknown              TaskRunStatusReason = "Unknown"
	TaskRunStatusReasonNone                 TaskRunStatusReason = "None"
	TaskRunStatusReasonOperatorPaused       TaskRunStatusReason = "OperatorPaused"
	TaskRunStatusReasonPhaseGate            TaskRunStatusReason = "PhaseGate"
	TaskRunStatusReasonSafetyGate           TaskRunStatusReason = "SafetyGate"
	TaskRunStatusReasonConflictRetryTimeout TaskRunStatusReason = "ConflictRetryTimeout"
)

var taskRunStatusReasonChoiceMap = map[TaskRunStatusReason]flowv1.OperationRunStatusReason{
	TaskRunStatusReasonUnknown:              flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_UNKNOWN,
	TaskRunStatusReasonNone:                 flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_NONE,
	TaskRunStatusReasonOperatorPaused:       flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_OPERATOR_PAUSED,
	TaskRunStatusReasonPhaseGate:            flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_PHASE_GATE,
	TaskRunStatusReasonSafetyGate:           flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_SAFETY_GATE,
	TaskRunStatusReasonConflictRetryTimeout: flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_CONFLICT_RETRY_TIMEOUT,
}

// FromProto populates the REST status reason from a Flow enum value.
func (r *TaskRunStatusReason) FromProto(p flowv1.OperationRunStatusReason) {
	if r == nil {
		return
	}
	for rest, proto := range taskRunStatusReasonChoiceMap {
		if proto == p {
			*r = rest
			return
		}
	}
	*r = TaskRunStatusReasonUnknown
}

// TaskRunTargetStatus enumerates per-rack target execution states.
type TaskRunTargetStatus string

const (
	TaskRunTargetStatusUnknown    TaskRunTargetStatus = "Unknown"
	TaskRunTargetStatusPending    TaskRunTargetStatus = "Pending"
	TaskRunTargetStatusBlocked    TaskRunTargetStatus = "Blocked"
	TaskRunTargetStatusSubmitted  TaskRunTargetStatus = "Submitted"
	TaskRunTargetStatusCompleted  TaskRunTargetStatus = "Completed"
	TaskRunTargetStatusFailed     TaskRunTargetStatus = "Failed"
	TaskRunTargetStatusTerminated TaskRunTargetStatus = "Terminated"
	TaskRunTargetStatusSkipped    TaskRunTargetStatus = "Skipped"
	TaskRunTargetStatusClaimed    TaskRunTargetStatus = "Claimed"
)

var taskRunTargetStatusChoiceMap = map[TaskRunTargetStatus]flowv1.OperationRunTargetStatus{
	TaskRunTargetStatusUnknown:    flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN,
	TaskRunTargetStatusPending:    flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_PENDING,
	TaskRunTargetStatusBlocked:    flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_BLOCKED,
	TaskRunTargetStatusSubmitted:  flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SUBMITTED,
	TaskRunTargetStatusCompleted:  flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_COMPLETED,
	TaskRunTargetStatusFailed:     flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_FAILED,
	TaskRunTargetStatusTerminated: flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_TERMINATED,
	TaskRunTargetStatusSkipped:    flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SKIPPED,
	TaskRunTargetStatusClaimed:    flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_CLAIMED,
}

var validTaskRunTargetStatuses = []TaskRunTargetStatus{
	TaskRunTargetStatusPending,
	TaskRunTargetStatusBlocked,
	TaskRunTargetStatusSubmitted,
	TaskRunTargetStatusCompleted,
	TaskRunTargetStatusFailed,
	TaskRunTargetStatusTerminated,
	TaskRunTargetStatusSkipped,
	TaskRunTargetStatusClaimed,
}

var validTaskRunTargetStatusesAny = func() []any {
	out := make([]any, len(validTaskRunTargetStatuses))
	for i, s := range validTaskRunTargetStatuses {
		out[i] = s
	}
	return out
}()

// ToProto converts the REST target status to its Flow enum value.
func (s TaskRunTargetStatus) ToProto() flowv1.OperationRunTargetStatus {
	if v, ok := taskRunTargetStatusChoiceMap[s]; ok {
		return v
	}
	return flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN
}

// FromProto populates the REST target status from a Flow enum value.
func (s *TaskRunTargetStatus) FromProto(p flowv1.OperationRunTargetStatus) {
	if s == nil {
		return
	}
	for rest, proto := range taskRunTargetStatusChoiceMap {
		if proto == p {
			*s = rest
			return
		}
	}
	*s = TaskRunTargetStatusUnknown
}

// ~~~~~ Response model ~~~~~ //

// APITaskRun is the API response model for a Flow operation run. List
// responses populate the summary fields only; get responses additionally
// populate Stats when the caller requests derived stats.
type APITaskRun struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	OperationType APIOperationType `json:"operationType"`
	OperationCode string           `json:"operationCode"`
	Status        TaskRunStatus    `json:"status"`
	// StatusReason explains why a run is paused or terminal (e.g. PhaseGate,
	// SafetyGate). "None" when there is no qualifying reason.
	StatusReason  TaskRunStatusReason `json:"statusReason"`
	StatusMessage string              `json:"statusMessage"`
	TotalPhases   int32               `json:"totalPhases"`
	Created       time.Time           `json:"created"`
	Updated       time.Time           `json:"updated"`
	Started       *time.Time          `json:"started"`
	Finished      *time.Time          `json:"finished"`
	// Stats is present only when the caller requests derived stats on a get.
	Stats *APITaskRunStats `json:"stats,omitempty"`
}

// APITaskRunStats summarizes target outcomes for the active phase and for all
// phases processed so far.
type APITaskRunStats struct {
	CurrentPhase    APITaskRunPhaseStats `json:"currentPhase"`
	CumulativePhase APITaskRunPhaseStats `json:"cumulativePhase"`
}

// APITaskRunPhaseStats summarizes target outcomes for one phase scope.
type APITaskRunPhaseStats struct {
	PhaseIndex      int32                   `json:"phaseIndex"`
	SelectedTargets int32                   `json:"selectedTargets"`
	OutcomeCounts   APITaskRunOutcomeCounts `json:"outcomeCounts"`
}

// APITaskRunOutcomeCounts counts terminal target outcomes within a phase scope.
type APITaskRunOutcomeCounts struct {
	Completed  int32 `json:"completed"`
	Failed     int32 `json:"failed"`
	Terminated int32 `json:"terminated"`
	Skipped    int32 `json:"skipped"`
}

// FromProtoSummary populates the summary fields shared by list and get
// responses from an OperationRunSummary.
func (a *APITaskRun) FromProtoSummary(s *flowv1.OperationRunSummary) {
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
		a.Status.FromProto(st.GetStatus())
		a.StatusReason.FromProto(st.GetReason())
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

// FromProto populates an APITaskRun from a full OperationRun, including
// derived stats when Flow computed them.
func (a *APITaskRun) FromProto(run *flowv1.OperationRun) {
	if run == nil {
		return
	}
	a.FromProtoSummary(run.GetSummary())
	if stats := run.GetStats(); stats != nil {
		a.Stats = newAPITaskRunStats(stats)
	}
}

func newAPITaskRunStats(s *flowv1.OperationRunStats) *APITaskRunStats {
	if s == nil {
		return nil
	}
	return &APITaskRunStats{
		CurrentPhase:    phaseStatsFromProto(s.GetCurrentPhaseStats()),
		CumulativePhase: phaseStatsFromProto(s.GetCumulativePhaseStats()),
	}
}

func phaseStatsFromProto(p *flowv1.OperationRunPhaseStats) APITaskRunPhaseStats {
	out := APITaskRunPhaseStats{}
	if p == nil {
		return out
	}
	out.PhaseIndex = p.GetPhaseIndex()
	out.SelectedTargets = p.GetSelectedTargets()
	if c := p.GetOutcomeCounts(); c != nil {
		out.OutcomeCounts = APITaskRunOutcomeCounts{
			Completed:  c.GetCompleted(),
			Failed:     c.GetFailed(),
			Terminated: c.GetTerminated(),
			Skipped:    c.GetSkipped(),
		}
	}
	return out
}

// ~~~~~ Target response model ~~~~~ //

// APITaskRunTarget is the API response model for one materialized rack
// execution target of a run. TaskID references the Task the run
// submitted for this rack (nil until submission); clients drill into execution
// detail via GET /task/{taskId}.
type APITaskRunTarget struct {
	ID            string              `json:"id"`
	RunID         string              `json:"runId"`
	RackID        string              `json:"rackId"`
	SequenceIndex int32               `json:"sequenceIndex"`
	PhaseIndex    int32               `json:"phaseIndex"`
	TaskID        *string             `json:"taskId"`
	Status        TaskRunTargetStatus `json:"status"`
	Message       string              `json:"message"`
	Created       time.Time           `json:"created"`
	Updated       time.Time           `json:"updated"`
}

// FromProto populates an APITaskRunTarget from an OperationRunTarget.
func (t *APITaskRunTarget) FromProto(p *flowv1.OperationRunTarget) {
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
	t.Status.FromProto(p.GetStatus())
	t.Message = p.GetMessage()
	if ts := p.GetCreatedAt(); ts != nil {
		t.Created = ts.AsTime().UTC()
	}
	if ts := p.GetUpdatedAt(); ts != nil {
		t.Updated = ts.AsTime().UTC()
	}
}

// ~~~~~ Get (siteId + includeStats via query) ~~~~~ //

// APITaskRunGetRequest captures query parameters for GET /task/run/{id}.
type APITaskRunGetRequest struct {
	SiteID       string `query:"siteId"`
	IncludeStats bool   `query:"includeStats"`
}

func (r *APITaskRunGetRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
	)
}

// ~~~~~ List ~~~~~ //

// APITaskRunGetAllRequest binds query parameters for GET /task/run. Pagination
// is bound separately via pagination.PageRequest.
type APITaskRunGetAllRequest struct {
	SiteID        string           `query:"siteId"`
	Status        TaskRunStatus    `query:"status"`
	OperationType APIOperationType `query:"operationType"`
}

func (r *APITaskRunGetAllRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.OperationType,
			validation.When(r.OperationType != "",
				validation.In(validOperationTypesAny...).Error(
					fmt.Sprintf("operationType must be one of %v", validOperationTypes)))),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validTaskRunStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validTaskRunStatuses)))),
	)
}

// ToProto converts the list filters into the Flow ListOperationRunsRequest.
func (r *APITaskRunGetAllRequest) ToProto(page pagination.PageRequest) (*flowv1.ListOperationRunsRequest, error) {
	req := &flowv1.ListOperationRunsRequest{}
	filter := &flowv1.OperationRunFilter{}
	hasFilter := false

	if r.Status != "" {
		status := r.Status.ToProto()
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
func (r *APITaskRunGetAllRequest) QueryValues(page pagination.PageRequest) url.Values {
	v := url.Values{}
	v.Set("siteId", r.SiteID)
	if r.Status != "" {
		v.Set("status", string(r.Status))
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

// APITaskRunTargetGetAllRequest binds query parameters for
// GET /task/run/{id}/target.
type APITaskRunTargetGetAllRequest struct {
	SiteID     string              `query:"siteId"`
	Status     TaskRunTargetStatus `query:"status"`
	PhaseScope string              `query:"phaseScope"`
}

var validTaskRunPhaseScopes = []string{"currentPhase", "completedPhases", "currentAndCompletedPhases"}

var validTaskRunPhaseScopesAny = func() []any {
	out := make([]any, len(validTaskRunPhaseScopes))
	for i, s := range validTaskRunPhaseScopes {
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

func (r *APITaskRunTargetGetAllRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validTaskRunTargetStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validTaskRunTargetStatuses)))),
		validation.Field(&r.PhaseScope,
			validation.When(r.PhaseScope != "",
				validation.In(validTaskRunPhaseScopesAny...).Error(
					fmt.Sprintf("phaseScope must be one of %v", validTaskRunPhaseScopes)))),
	)
}

// ToProto converts the target-list filters into the Flow
// ListOperationRunTargetsRequest. status UNKNOWN means no status filter.
func (r *APITaskRunTargetGetAllRequest) ToProto(runID string, page pagination.PageRequest) *flowv1.ListOperationRunTargetsRequest {
	req := &flowv1.ListOperationRunTargetsRequest{
		OperationRunId: &flowv1.UUID{Id: runID},
		Status:         flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN,
		PhaseScope:     apiToProtoRunPhaseScope[r.PhaseScope],
	}
	if r.Status != "" {
		req.Status = r.Status.ToProto()
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
func (r *APITaskRunTargetGetAllRequest) QueryValues(page pagination.PageRequest) url.Values {
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

// APITaskRunSiteRequest is the shared JSON body for the pause/resume/advance
// lifecycle actions, which need only the target Site.
type APITaskRunSiteRequest struct {
	SiteID string `json:"siteId"`
}

func (r *APITaskRunSiteRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APITaskRunAdvanceRequest is the JSON body for POST /task/run/{id}/advance.
// ExpectedPhaseIndex is an optional guard: when set, the phase that would be
// opened must match, otherwise Flow rejects the advance.
type APITaskRunAdvanceRequest struct {
	SiteID             string `json:"siteId"`
	ExpectedPhaseIndex *int32 `json:"expectedPhaseIndex"`
}

func (r *APITaskRunAdvanceRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APITaskRunCancelRequest is the JSON body for POST /task/run/{id}/cancel.
type APITaskRunCancelRequest struct {
	SiteID string `json:"siteId"`
	Reason string `json:"reason"`
}

func (r *APITaskRunCancelRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// ~~~~~ Create ~~~~~ //

// safety-gate scope maps between the API string and Flow's enum. The empty
// value maps to the current-phase default.
var validTaskRunGateScopes = []string{"currentPhase", "cumulativeRun"}

var validTaskRunGateScopesAny = func() []any {
	out := make([]any, len(validTaskRunGateScopes))
	for i, s := range validTaskRunGateScopes {
		out[i] = s
	}
	return out
}()

var apiToProtoGateScope = map[string]flowv1.OperationRunSafetyGateScope{
	"":              flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"currentPhase":  flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"cumulativeRun": flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CUMULATIVE_RUN,
}

// APITaskRunCreateRequest is the JSON body for POST /task/run. A run executes
// exactly one operation (currently firmware) across a candidate set of racks,
// narrowed by an optional selector and divided into phases by an optional phase
// policy. operationType is inferred from the operation and is not accepted here.
type APITaskRunCreateRequest struct {
	SiteID      string `json:"siteId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Selector narrows the candidate racks. Omit to target the full candidate
	// scope (100%).
	Selector  *APITaskRunSelector `json:"selector"`
	Options   APITaskRunOptions   `json:"options"`
	Operation APITaskRunOperation `json:"operation"`
}

// APITaskRunSelector selects a subset of candidate racks. Percentage is the
// only supported selector today.
type APITaskRunSelector struct {
	Percentage *APITaskRunPercentageSelector `json:"percentage"`
}

// APITaskRunPercentageSelector selects a percentage of the candidate racks.
// Seed is optional; when omitted Flow generates and stores one so the cohort
// is deterministic and auditable.
type APITaskRunPercentageSelector struct {
	Percent int32  `json:"percent"`
	Seed    string `json:"seed"`
}

// APITaskRunOptions configures execution policy for the run.
type APITaskRunOptions struct {
	// MaxConcurrentTargets caps how many targets may have active child tasks at
	// once. Required, must be greater than zero.
	MaxConcurrentTargets int32                     `json:"maxConcurrentTargets"`
	SafetyPolicy         *APITaskRunSafetyPolicy   `json:"safetyPolicy"`
	ConflictPolicy       *APITaskRunConflictPolicy `json:"conflictPolicy"`
	OrderingPolicy       *APITaskRunOrderingPolicy `json:"orderingPolicy"`
	PhasePolicy          *APITaskRunPhasePolicy    `json:"phasePolicy"`
}

// APITaskRunSafetyPolicy is a set of gates that pause the run when any
// one of them trips (OR composition).
type APITaskRunSafetyPolicy struct {
	Gates []APITaskRunSafetyGate `json:"gates"`
}

// APITaskRunSafetyGate is exactly one of failureRate or failureCount.
type APITaskRunSafetyGate struct {
	FailureRate  *APITaskRunFailureRateGate  `json:"failureRate"`
	FailureCount *APITaskRunFailureCountGate `json:"failureCount"`
}

// APITaskRunFailureRateGate pauses when failed/planned reaches ThresholdPercent
// for the scope.
type APITaskRunFailureRateGate struct {
	Scope            string `json:"scope"`
	ThresholdPercent int32  `json:"thresholdPercent"`
}

// APITaskRunFailureCountGate pauses when failed targets reach ThresholdCount
// for the scope.
type APITaskRunFailureCountGate struct {
	Scope          string `json:"scope"`
	ThresholdCount int32  `json:"thresholdCount"`
}

// APITaskRunConflictPolicy configures how blocked targets are retried. Retry
// is the only supported strategy today.
type APITaskRunConflictPolicy struct {
	Retry *APITaskRunConflictRetry `json:"retry"`
}

// APITaskRunConflictRetry configures retry backoff for blocked targets.
// Durations are Go duration strings (e.g. "30m", "10s"); empty means "use the
// operation default".
type APITaskRunConflictRetry struct {
	RetryTimeout      string `json:"retryTimeout"`
	InitialRetryDelay string `json:"initialRetryDelay"`
	MaxRetryDelay     string `json:"maxRetryDelay"`
}

// APITaskRunOrderingPolicy controls the order in which targets are processed.
// Random is the only supported ordering today.
type APITaskRunOrderingPolicy struct {
	Random *APITaskRunRandomOrdering `json:"random"`
}

// APITaskRunRandomOrdering orders targets randomly. Seed is optional; Flow
// generates and stores one when omitted.
type APITaskRunRandomOrdering struct {
	Seed string `json:"seed"`
}

// APITaskRunPhasePolicy divides the selected targets into phases. Exactly one
// of equal, percentage, or count may be set; omit the whole policy for a single
// phase covering all targets.
type APITaskRunPhasePolicy struct {
	Equal      *APITaskRunEqualPhases      `json:"equal"`
	Percentage *APITaskRunPercentagePhases `json:"percentage"`
	Count      *APITaskRunCountPhases      `json:"count"`
	// AutoAdvance, when true, advances phases automatically as long as safety
	// gates are not tripped. When false (default) each completed phase pauses at
	// a phase gate until advanced explicitly.
	AutoAdvance bool `json:"autoAdvance"`
}

// APITaskRunEqualPhases splits targets into PhaseCount roughly equal phases.
type APITaskRunEqualPhases struct {
	PhaseCount int32 `json:"phaseCount"`
}

// APITaskRunPercentagePhases splits targets by percentage. Values must sum to
// 100.
type APITaskRunPercentagePhases struct {
	Phases []int32 `json:"phases"`
}

// APITaskRunCountPhases splits targets by explicit counts. A generated final
// phase covers any remaining targets.
type APITaskRunCountPhases struct {
	Phases []int32 `json:"phases"`
}

// APITaskRunOperation is the operation the run executes. Firmware is the only
// supported operation today.
type APITaskRunOperation struct {
	Firmware *APITaskRunFirmwareOperation `json:"firmware"`
	// ExcludeRunIDs excludes racks materialized by prior runs from
	// this run's candidate scope.
	ExcludeRunIDs []string `json:"excludeRunIds"`
}

// APITaskRunFirmwareOperation configures a firmware rollout.
type APITaskRunFirmwareOperation struct {
	Version                string   `json:"version"`
	RuleID                 *string  `json:"ruleId"`
	OverrideReadinessCheck bool     `json:"overrideReadinessCheck"`
	SubTargets             []string `json:"subTargets"`
}

// Validate enforces request shape only; Flow performs semantic validation
// (selector ranges, phase math, operation code membership) server-side.
func (r *APITaskRunCreateRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.Name, validation.Required.Error("name is required")),
		validation.Field(&r.Options),
		validation.Field(&r.Operation),
	)
}

// Validate enforces the execution policy shape. The nested policies validate
// themselves; ozzo skips the ones left nil.
func (o APITaskRunOptions) Validate() error {
	return validation.ValidateStruct(&o,
		// Required rejects zero (the threshold rules treat it as empty and skip
		// it); Min rejects negatives.
		validation.Field(&o.MaxConcurrentTargets,
			validation.Required.Error("must be greater than zero"),
			validation.Min(1).Error("must be greater than zero")),
		validation.Field(&o.SafetyPolicy),
		validation.Field(&o.ConflictPolicy),
		validation.Field(&o.PhasePolicy),
	)
}

func (p APITaskRunSafetyPolicy) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Gates),
	)
}

// Validate requires exactly one gate kind. ozzo cannot express a choice
// between sibling fields declaratively.
func (g APITaskRunSafetyGate) Validate() error {
	if (g.FailureRate == nil) == (g.FailureCount == nil) {
		return errors.New("must set exactly one of failureRate or failureCount")
	}
	return validation.ValidateStruct(&g,
		validation.Field(&g.FailureRate),
		validation.Field(&g.FailureCount),
	)
}

func (g APITaskRunFailureRateGate) Validate() error {
	return validation.ValidateStruct(&g,
		validation.Field(&g.Scope,
			validation.In(validTaskRunGateScopesAny...).Error(
				fmt.Sprintf("must be one of %v", validTaskRunGateScopes))),
	)
}

func (g APITaskRunFailureCountGate) Validate() error {
	return validation.ValidateStruct(&g,
		validation.Field(&g.Scope,
			validation.In(validTaskRunGateScopesAny...).Error(
				fmt.Sprintf("must be one of %v", validTaskRunGateScopes))),
	)
}

func (p APITaskRunConflictPolicy) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Retry),
	)
}

// Validate rejects unparseable durations here so ToProto stays a pure mapper.
func (r APITaskRunConflictRetry) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.RetryTimeout, validation.By(validateOptionalDuration)),
		validation.Field(&r.InitialRetryDelay, validation.By(validateOptionalDuration)),
		validation.Field(&r.MaxRetryDelay, validation.By(validateOptionalDuration)),
	)
}

// Validate allows at most one phase division. ozzo cannot express a choice
// between sibling fields declaratively.
func (p APITaskRunPhasePolicy) Validate() error {
	set := 0
	for _, isSet := range []bool{p.Equal != nil, p.Percentage != nil, p.Count != nil} {
		if isSet {
			set++
		}
	}
	if set > 1 {
		return errors.New("must set at most one of equal, percentage, count")
	}
	return nil
}

// Validate requires the firmware operation, the only kind Flow supports today.
func (o APITaskRunOperation) Validate() error {
	return validation.ValidateStruct(&o,
		validation.Field(&o.Firmware, validation.Required.Error("firmware is required")),
	)
}

func (f APITaskRunFirmwareOperation) Validate() error {
	return validation.ValidateStruct(&f,
		validation.Field(&f.Version, validation.Required.Error("version is required")),
	)
}

// validateOptionalDuration accepts an empty string, meaning "use the operation
// default", or any Go duration string.
func validateOptionalDuration(value any) error {
	s, ok := value.(string)
	if !ok || s == "" {
		return nil
	}
	if _, err := time.ParseDuration(s); err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	return nil
}

// ToProto converts the create request into the Flow CreateOperationRunRequest.
func (r *APITaskRunCreateRequest) ToProto() (*flowv1.CreateOperationRunRequest, error) {
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

func (o APITaskRunOptions) toProto() (*flowv1.OperationRunOptions, error) {
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

func (g APITaskRunSafetyGate) toProto() *flowv1.OperationRunSafetyGate {
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

func (r APITaskRunConflictRetry) toProto() (*flowv1.OperationRunConflictRetryPolicy, error) {
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

func (p APITaskRunPhasePolicy) toProto() *flowv1.OperationRunPhasePolicy {
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

func (o APITaskRunOperation) toProto() (*flowv1.OperationRunOperation, error) {
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
