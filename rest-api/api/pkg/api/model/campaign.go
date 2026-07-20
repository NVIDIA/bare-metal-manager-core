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

// A Campaign is the REST representation of Flow's operation run: a phased,
// policy-gated rollout of one operation across many racks. Each campaign
// materializes a set of per-rack targets (APICampaignTarget), and each target
// drives at most one Task. Callers drill into execution detail via the Task
// endpoints using APICampaignTarget.TaskID.

// ~~~~~ Status enums ~~~~~ //

var protoToAPICampaignStatus = map[flowv1.OperationRunStatus]string{
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN:                 "Unknown",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PENDING:                 "Pending",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_RUNNING:                 "Running",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_PAUSED:                  "Paused",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED:               "Completed",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_CANCELLED:               "Cancelled",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_FAILED:                  "Failed",
	flowv1.OperationRunStatus_OPERATION_RUN_STATUS_COMPLETED_WITH_FAILURES: "CompletedWithFailures",
}

// validCampaignStatuses lists the run statuses accepted as a list filter.
// UNKNOWN is intentionally excluded (it is not a filterable state).
var validCampaignStatuses = []string{
	"Pending", "Running", "Paused", "Completed", "Cancelled", "Failed", "CompletedWithFailures",
}

var validCampaignStatusesAny = func() []any {
	out := make([]any, len(validCampaignStatuses))
	for i, s := range validCampaignStatuses {
		out[i] = s
	}
	return out
}()

// apiToProtoCampaignStatus is the reverse of protoToAPICampaignStatus for the
// filterable statuses.
var apiToProtoCampaignStatus = func() map[string]flowv1.OperationRunStatus {
	out := make(map[string]flowv1.OperationRunStatus, len(protoToAPICampaignStatus))
	for proto, api := range protoToAPICampaignStatus {
		if proto == flowv1.OperationRunStatus_OPERATION_RUN_STATUS_UNKNOWN {
			continue
		}
		out[api] = proto
	}
	return out
}()

var protoToAPICampaignStatusReason = map[flowv1.OperationRunStatusReason]string{
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_UNKNOWN:                "Unknown",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_NONE:                   "None",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_OPERATOR_PAUSED:        "OperatorPaused",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_PHASE_GATE:             "PhaseGate",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_SAFETY_GATE:            "SafetyGate",
	flowv1.OperationRunStatusReason_OPERATION_RUN_STATUS_REASON_CONFLICT_RETRY_TIMEOUT: "ConflictRetryTimeout",
}

// APICampaignTargetStatus enumerates per-rack target execution states.
type APICampaignTargetStatus string

const (
	APICampaignTargetStatusUnknown    APICampaignTargetStatus = "Unknown"
	APICampaignTargetStatusPending    APICampaignTargetStatus = "Pending"
	APICampaignTargetStatusBlocked    APICampaignTargetStatus = "Blocked"
	APICampaignTargetStatusSubmitted  APICampaignTargetStatus = "Submitted"
	APICampaignTargetStatusCompleted  APICampaignTargetStatus = "Completed"
	APICampaignTargetStatusFailed     APICampaignTargetStatus = "Failed"
	APICampaignTargetStatusTerminated APICampaignTargetStatus = "Terminated"
	APICampaignTargetStatusSkipped    APICampaignTargetStatus = "Skipped"
	APICampaignTargetStatusClaimed    APICampaignTargetStatus = "Claimed"
)

var validCampaignTargetStatuses = []APICampaignTargetStatus{
	APICampaignTargetStatusPending,
	APICampaignTargetStatusBlocked,
	APICampaignTargetStatusSubmitted,
	APICampaignTargetStatusCompleted,
	APICampaignTargetStatusFailed,
	APICampaignTargetStatusTerminated,
	APICampaignTargetStatusSkipped,
	APICampaignTargetStatusClaimed,
}

var validCampaignTargetStatusesAny = func() []any {
	out := make([]any, len(validCampaignTargetStatuses))
	for i, s := range validCampaignTargetStatuses {
		out[i] = s
	}
	return out
}()

var protoToAPICampaignTargetStatus = map[flowv1.OperationRunTargetStatus]APICampaignTargetStatus{
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN:    APICampaignTargetStatusUnknown,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_PENDING:    APICampaignTargetStatusPending,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_BLOCKED:    APICampaignTargetStatusBlocked,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SUBMITTED:  APICampaignTargetStatusSubmitted,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_COMPLETED:  APICampaignTargetStatusCompleted,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_FAILED:     APICampaignTargetStatusFailed,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_TERMINATED: APICampaignTargetStatusTerminated,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_SKIPPED:    APICampaignTargetStatusSkipped,
	flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_CLAIMED:    APICampaignTargetStatusClaimed,
}

var apiToProtoCampaignTargetStatus = func() map[APICampaignTargetStatus]flowv1.OperationRunTargetStatus {
	out := make(map[APICampaignTargetStatus]flowv1.OperationRunTargetStatus, len(protoToAPICampaignTargetStatus))
	for k, v := range protoToAPICampaignTargetStatus {
		out[v] = k
	}
	return out
}()

// ~~~~~ Response model ~~~~~ //

// APICampaign is the API response model for a Flow operation run. List
// responses populate the summary fields only; get responses additionally
// populate Stats when the caller requests derived stats.
type APICampaign struct {
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
	Stats *APICampaignStats `json:"stats,omitempty"`
}

// APICampaignStats summarizes target outcomes for the active phase and for all
// phases processed so far.
type APICampaignStats struct {
	CurrentPhase    APICampaignPhaseStats `json:"currentPhase"`
	CumulativePhase APICampaignPhaseStats `json:"cumulativePhase"`
}

// APICampaignPhaseStats summarizes target outcomes for one phase scope.
type APICampaignPhaseStats struct {
	PhaseIndex      int32                    `json:"phaseIndex"`
	SelectedTargets int32                    `json:"selectedTargets"`
	OutcomeCounts   APICampaignOutcomeCounts `json:"outcomeCounts"`
}

// APICampaignOutcomeCounts counts terminal target outcomes within a phase scope.
type APICampaignOutcomeCounts struct {
	Completed  int32 `json:"completed"`
	Failed     int32 `json:"failed"`
	Terminated int32 `json:"terminated"`
	Skipped    int32 `json:"skipped"`
}

// FromProtoSummary populates the summary fields shared by list and get
// responses from an OperationRunSummary.
func (a *APICampaign) FromProtoSummary(s *flowv1.OperationRunSummary) {
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
		a.Status = enumOr(protoToAPICampaignStatus, st.GetStatus(), "Unknown")
		a.StatusReason = enumOr(protoToAPICampaignStatusReason, st.GetReason(), "Unknown")
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

// FromProto populates an APICampaign from a full OperationRun, including
// derived stats when Flow computed them.
func (a *APICampaign) FromProto(run *flowv1.OperationRun) {
	if run == nil {
		return
	}
	a.FromProtoSummary(run.GetSummary())
	if stats := run.GetStats(); stats != nil {
		a.Stats = newAPICampaignStats(stats)
	}
}

func newAPICampaignStats(s *flowv1.OperationRunStats) *APICampaignStats {
	if s == nil {
		return nil
	}
	return &APICampaignStats{
		CurrentPhase:    phaseStatsFromProto(s.GetCurrentPhaseStats()),
		CumulativePhase: phaseStatsFromProto(s.GetCumulativePhaseStats()),
	}
}

func phaseStatsFromProto(p *flowv1.OperationRunPhaseStats) APICampaignPhaseStats {
	out := APICampaignPhaseStats{}
	if p == nil {
		return out
	}
	out.PhaseIndex = p.GetPhaseIndex()
	out.SelectedTargets = p.GetSelectedTargets()
	if c := p.GetOutcomeCounts(); c != nil {
		out.OutcomeCounts = APICampaignOutcomeCounts{
			Completed:  c.GetCompleted(),
			Failed:     c.GetFailed(),
			Terminated: c.GetTerminated(),
			Skipped:    c.GetSkipped(),
		}
	}
	return out
}

// NewAPICampaignFromProto builds an APICampaign from a full OperationRun.
func NewAPICampaignFromProto(run *flowv1.OperationRun) *APICampaign {
	a := &APICampaign{}
	a.FromProto(run)
	return a
}

// NewAPICampaignFromSummary builds an APICampaign from an OperationRunSummary.
func NewAPICampaignFromSummary(s *flowv1.OperationRunSummary) *APICampaign {
	a := &APICampaign{}
	a.FromProtoSummary(s)
	return a
}

// ~~~~~ Target response model ~~~~~ //

// APICampaignTarget is the API response model for one materialized rack
// execution target of a campaign. TaskID references the Task the campaign
// submitted for this rack (nil until submission); clients drill into execution
// detail via GET /task/{taskId}.
type APICampaignTarget struct {
	ID            string                  `json:"id"`
	CampaignID    string                  `json:"campaignId"`
	RackID        string                  `json:"rackId"`
	SequenceIndex int32                   `json:"sequenceIndex"`
	PhaseIndex    int32                   `json:"phaseIndex"`
	TaskID        *string                 `json:"taskId"`
	Status        APICampaignTargetStatus `json:"status"`
	Message       string                  `json:"message"`
	Created       time.Time               `json:"created"`
	Updated       time.Time               `json:"updated"`
}

// FromProto populates an APICampaignTarget from an OperationRunTarget.
func (t *APICampaignTarget) FromProto(p *flowv1.OperationRunTarget) {
	if p == nil {
		return
	}
	if p.GetId() != nil {
		t.ID = p.GetId().GetId()
	}
	if p.GetOperationRunId() != nil {
		t.CampaignID = p.GetOperationRunId().GetId()
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
	t.Status = enumOr(protoToAPICampaignTargetStatus, p.GetStatus(), APICampaignTargetStatusUnknown)
	t.Message = p.GetMessage()
	if ts := p.GetCreatedAt(); ts != nil {
		t.Created = ts.AsTime().UTC()
	}
	if ts := p.GetUpdatedAt(); ts != nil {
		t.Updated = ts.AsTime().UTC()
	}
}

// NewAPICampaignTarget builds an APICampaignTarget from an OperationRunTarget.
func NewAPICampaignTarget(p *flowv1.OperationRunTarget) *APICampaignTarget {
	t := &APICampaignTarget{}
	t.FromProto(p)
	return t
}

// ~~~~~ Get (siteId + includeStats via query) ~~~~~ //

// APICampaignGetRequest captures query parameters for GET /campaign/{id}.
type APICampaignGetRequest struct {
	SiteID       string `query:"siteId"`
	IncludeStats bool   `query:"includeStats"`
}

func (r *APICampaignGetRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
	)
}

// ~~~~~ List ~~~~~ //

// APICampaignListRequest binds query parameters for GET /campaign. Pagination
// is bound separately via pagination.PageRequest.
type APICampaignListRequest struct {
	SiteID        string           `query:"siteId"`
	Status        string           `query:"status"`
	OperationType APIOperationType `query:"operationType"`
}

func (r *APICampaignListRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.OperationType,
			validation.When(r.OperationType != "",
				validation.In(validOperationTypesAny...).Error(
					fmt.Sprintf("operationType must be one of %v", validOperationTypes)))),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validCampaignStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validCampaignStatuses)))),
	)
}

// ToProto converts the list filters into the Flow ListOperationRunsRequest.
func (r *APICampaignListRequest) ToProto(page pagination.PageRequest) (*flowv1.ListOperationRunsRequest, error) {
	req := &flowv1.ListOperationRunsRequest{}
	filter := &flowv1.OperationRunFilter{}
	hasFilter := false

	if r.Status != "" {
		status, ok := apiToProtoCampaignStatus[r.Status]
		if !ok {
			return nil, fmt.Errorf("invalid status %q (expected one of %v)", r.Status, validCampaignStatuses)
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
func (r *APICampaignListRequest) QueryValues(page pagination.PageRequest) url.Values {
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

// APICampaignTargetsListRequest binds query parameters for
// GET /campaign/{id}/target.
type APICampaignTargetsListRequest struct {
	SiteID     string                  `query:"siteId"`
	Status     APICampaignTargetStatus `query:"status"`
	PhaseScope string                  `query:"phaseScope"`
}

var validCampaignPhaseScopes = []string{"currentPhase", "completedPhases", "currentAndCompletedPhases"}

var validCampaignPhaseScopesAny = func() []any {
	out := make([]any, len(validCampaignPhaseScopes))
	for i, s := range validCampaignPhaseScopes {
		out[i] = s
	}
	return out
}()

var apiToProtoCampaignPhaseScope = map[string]flowv1.OperationRunTargetPhaseScope{
	"":                          flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_PHASE,
	"currentPhase":              flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_PHASE,
	"completedPhases":           flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_COMPLETED_PHASES,
	"currentAndCompletedPhases": flowv1.OperationRunTargetPhaseScope_OPERATION_RUN_TARGET_PHASE_SCOPE_CURRENT_AND_COMPLETED_PHASES,
}

func (r *APICampaignTargetsListRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.Status,
			validation.When(r.Status != "",
				validation.In(validCampaignTargetStatusesAny...).Error(
					fmt.Sprintf("status must be one of %v", validCampaignTargetStatuses)))),
		validation.Field(&r.PhaseScope,
			validation.When(r.PhaseScope != "",
				validation.In(validCampaignPhaseScopesAny...).Error(
					fmt.Sprintf("phaseScope must be one of %v", validCampaignPhaseScopes)))),
	)
}

// ToProto converts the target-list filters into the Flow
// ListOperationRunTargetsRequest. status UNKNOWN means no status filter.
func (r *APICampaignTargetsListRequest) ToProto(campaignID string, page pagination.PageRequest) *flowv1.ListOperationRunTargetsRequest {
	req := &flowv1.ListOperationRunTargetsRequest{
		OperationRunId: &flowv1.UUID{Id: campaignID},
		Status:         flowv1.OperationRunTargetStatus_OPERATION_RUN_TARGET_STATUS_UNKNOWN,
		PhaseScope:     apiToProtoCampaignPhaseScope[r.PhaseScope],
	}
	if r.Status != "" {
		if s, ok := apiToProtoCampaignTargetStatus[r.Status]; ok {
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
func (r *APICampaignTargetsListRequest) QueryValues(page pagination.PageRequest) url.Values {
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

// APICampaignSiteRequest is the shared JSON body for the pause/resume/advance
// lifecycle actions, which need only the target Site.
type APICampaignSiteRequest struct {
	SiteID string `json:"siteId"`
}

func (r *APICampaignSiteRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APICampaignAdvanceRequest is the JSON body for POST /campaign/{id}/advance.
// ExpectedPhaseIndex is an optional guard: when set, the phase that would be
// opened must match, otherwise Flow rejects the advance.
type APICampaignAdvanceRequest struct {
	SiteID             string `json:"siteId"`
	ExpectedPhaseIndex *int32 `json:"expectedPhaseIndex"`
}

func (r *APICampaignAdvanceRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// APICampaignCancelRequest is the JSON body for POST /campaign/{id}/cancel.
type APICampaignCancelRequest struct {
	SiteID string `json:"siteId"`
	Reason string `json:"reason"`
}

func (r *APICampaignCancelRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
	)
}

// ~~~~~ Create ~~~~~ //

// safety-gate scope maps between the API string and Flow's enum. The empty
// value maps to the current-phase default.
var validCampaignGateScopes = []string{"currentPhase", "cumulativeRun"}

var validCampaignGateScopesAny = func() []any {
	out := make([]any, len(validCampaignGateScopes))
	for i, s := range validCampaignGateScopes {
		out[i] = s
	}
	return out
}()

var apiToProtoGateScope = map[string]flowv1.OperationRunSafetyGateScope{
	"":              flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"currentPhase":  flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CURRENT_PHASE,
	"cumulativeRun": flowv1.OperationRunSafetyGateScope_OPERATION_RUN_SAFETY_GATE_SCOPE_CUMULATIVE_RUN,
}

// APICampaignCreateRequest is the JSON body for POST /campaign. A campaign runs
// exactly one operation (currently firmware) across a candidate set of racks,
// narrowed by an optional selector and divided into phases by an optional phase
// policy. operationType is inferred from the operation and is not accepted here.
type APICampaignCreateRequest struct {
	SiteID      string               `json:"siteId"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	// Selector narrows the candidate racks. Omit to target the full candidate
	// scope (100%).
	Selector  *APICampaignSelector `json:"selector"`
	Options   APICampaignOptions   `json:"options"`
	Operation APICampaignOperation `json:"operation"`
}

// APICampaignSelector selects a subset of candidate racks. Percentage is the
// only supported selector today.
type APICampaignSelector struct {
	Percentage *APICampaignPercentageSelector `json:"percentage"`
}

// APICampaignPercentageSelector selects a percentage of the candidate racks.
// Seed is optional; when omitted Flow generates and stores one so the cohort
// is deterministic and auditable.
type APICampaignPercentageSelector struct {
	Percent int32  `json:"percent"`
	Seed    string `json:"seed"`
}

// APICampaignOptions configures execution policy for the rollout.
type APICampaignOptions struct {
	// MaxConcurrentTargets caps how many targets may have active child tasks at
	// once. Required, must be greater than zero.
	MaxConcurrentTargets int32                      `json:"maxConcurrentTargets"`
	SafetyPolicy         *APICampaignSafetyPolicy   `json:"safetyPolicy"`
	ConflictPolicy       *APICampaignConflictPolicy `json:"conflictPolicy"`
	OrderingPolicy       *APICampaignOrderingPolicy `json:"orderingPolicy"`
	PhasePolicy          *APICampaignPhasePolicy    `json:"phasePolicy"`
}

// APICampaignSafetyPolicy is a set of gates that pause the campaign when any
// one of them trips (OR composition).
type APICampaignSafetyPolicy struct {
	Gates []APICampaignSafetyGate `json:"gates"`
}

// APICampaignSafetyGate is exactly one of failureRate or failureCount.
type APICampaignSafetyGate struct {
	FailureRate  *APICampaignFailureRateGate  `json:"failureRate"`
	FailureCount *APICampaignFailureCountGate `json:"failureCount"`
}

// APICampaignFailureRateGate pauses when failed/planned reaches ThresholdPercent
// for the scope.
type APICampaignFailureRateGate struct {
	Scope            string `json:"scope"`
	ThresholdPercent int32  `json:"thresholdPercent"`
}

// APICampaignFailureCountGate pauses when failed targets reach ThresholdCount
// for the scope.
type APICampaignFailureCountGate struct {
	Scope          string `json:"scope"`
	ThresholdCount int32  `json:"thresholdCount"`
}

// APICampaignConflictPolicy configures how blocked targets are retried. Retry
// is the only supported strategy today.
type APICampaignConflictPolicy struct {
	Retry *APICampaignConflictRetry `json:"retry"`
}

// APICampaignConflictRetry configures retry backoff for blocked targets.
// Durations are Go duration strings (e.g. "30m", "10s"); empty means "use the
// operation default".
type APICampaignConflictRetry struct {
	RetryTimeout      string `json:"retryTimeout"`
	InitialRetryDelay string `json:"initialRetryDelay"`
	MaxRetryDelay     string `json:"maxRetryDelay"`
}

// APICampaignOrderingPolicy controls the order in which targets are processed.
// Random is the only supported ordering today.
type APICampaignOrderingPolicy struct {
	Random *APICampaignRandomOrdering `json:"random"`
}

// APICampaignRandomOrdering orders targets randomly. Seed is optional; Flow
// generates and stores one when omitted.
type APICampaignRandomOrdering struct {
	Seed string `json:"seed"`
}

// APICampaignPhasePolicy divides the selected targets into phases. Exactly one
// of equal, percentage, or count may be set; omit the whole policy for a single
// phase covering all targets.
type APICampaignPhasePolicy struct {
	Equal      *APICampaignEqualPhases      `json:"equal"`
	Percentage *APICampaignPercentagePhases `json:"percentage"`
	Count      *APICampaignCountPhases      `json:"count"`
	// AutoAdvance, when true, advances phases automatically as long as safety
	// gates are not tripped. When false (default) each completed phase pauses at
	// a phase gate until advanced explicitly.
	AutoAdvance bool `json:"autoAdvance"`
}

// APICampaignEqualPhases splits targets into PhaseCount roughly equal phases.
type APICampaignEqualPhases struct {
	PhaseCount int32 `json:"phaseCount"`
}

// APICampaignPercentagePhases splits targets by percentage. Values must sum to
// 100.
type APICampaignPercentagePhases struct {
	Phases []int32 `json:"phases"`
}

// APICampaignCountPhases splits targets by explicit counts. A generated final
// phase covers any remaining targets.
type APICampaignCountPhases struct {
	Phases []int32 `json:"phases"`
}

// APICampaignOperation is the operation the campaign runs. Firmware is the only
// supported operation today.
type APICampaignOperation struct {
	Firmware *APICampaignFirmwareOperation `json:"firmware"`
	// ExcludeCampaignIDs excludes racks materialized by prior campaigns from
	// this campaign's candidate scope.
	ExcludeCampaignIDs []string `json:"excludeCampaignIds"`
}

// APICampaignFirmwareOperation configures a firmware rollout.
type APICampaignFirmwareOperation struct {
	Version                string   `json:"version"`
	RuleID                 *string  `json:"ruleId"`
	OverrideReadinessCheck bool     `json:"overrideReadinessCheck"`
	SubTargets             []string `json:"subTargets"`
}

// Validate enforces request shape only; Flow performs semantic validation
// (selector ranges, phase math, operation code membership) server-side.
func (r *APICampaignCreateRequest) Validate() error {
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
			return fmt.Errorf("options.safetyPolicy.gates[%d].scope must be one of %v", i, validCampaignGateScopes)
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

func gatesOf(p *APICampaignSafetyPolicy) []APICampaignSafetyGate {
	if p == nil {
		return nil
	}
	return p.Gates
}

func (g APICampaignSafetyGate) scope() string {
	if g.FailureRate != nil {
		return g.FailureRate.Scope
	}
	if g.FailureCount != nil {
		return g.FailureCount.Scope
	}
	return ""
}

// ToProto converts the create request into the Flow CreateOperationRunRequest.
func (r *APICampaignCreateRequest) ToProto() (*flowv1.CreateOperationRunRequest, error) {
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

func (o APICampaignOptions) toProto() (*flowv1.OperationRunOptions, error) {
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

func (g APICampaignSafetyGate) toProto() *flowv1.OperationRunSafetyGate {
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

func (r APICampaignConflictRetry) toProto() (*flowv1.OperationRunConflictRetryPolicy, error) {
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

func (p APICampaignPhasePolicy) toProto() *flowv1.OperationRunPhasePolicy {
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

func (o APICampaignOperation) toProto() (*flowv1.OperationRunOperation, error) {
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

	if len(o.ExcludeCampaignIDs) > 0 {
		excludes := make([]*flowv1.UUID, 0, len(o.ExcludeCampaignIDs))
		for _, id := range o.ExcludeCampaignIDs {
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
