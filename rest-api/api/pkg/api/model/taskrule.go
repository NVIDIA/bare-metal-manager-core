// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// Operation type strings exposed by the REST API. PascalCase follows the
// convention used elsewhere on the REST surface for enum-like string fields
// (TaskStatus, ComponentType, DiffType, BMCType). The internal Flow YAML
// rule files keep their snake_case spelling; conversion happens at the
// REST boundary via the maps below.
const (
	APIOperationTypePowerControl    = "PowerControl"
	APIOperationTypeFirmwareControl = "FirmwareControl"
)

// ProtoToAPIOperationTypeName maps Flow's protobuf OperationType enum to the
// string form used in API responses.
var ProtoToAPIOperationTypeName = map[flowv1.OperationType]string{
	flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL:    APIOperationTypePowerControl,
	flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL: APIOperationTypeFirmwareControl,
}

// apiToProtoOperationType is the reverse of ProtoToAPIOperationTypeName.
var apiToProtoOperationType = map[string]flowv1.OperationType{
	APIOperationTypePowerControl:    flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
	APIOperationTypeFirmwareControl: flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL,
}

// operationTypeFromAPI parses an API operationType string. The empty string
// is treated as "unset" (caller decides whether that is valid). Returns an
// error for unknown values so we don't silently accept garbage.
func operationTypeFromAPI(s string) (flowv1.OperationType, error) {
	if s == "" {
		return flowv1.OperationType_OPERATION_TYPE_UNKNOWN, nil
	}
	v, ok := apiToProtoOperationType[s]
	if !ok {
		return flowv1.OperationType_OPERATION_TYPE_UNKNOWN,
			fmt.Errorf("invalid operationType %q (expected one of: %s, %s)",
				s, APIOperationTypePowerControl, APIOperationTypeFirmwareControl)
	}
	return v, nil
}

// APITaskRule is the API response model for an Operation Rule.
// Top-level metadata uses camelCase; nested ruleDefinition uses snake_case to
// round-trip 1:1 with Flow's documented YAML/JSON schema so users converting
// existing YAML rule files only need to drop the same keys into the JSON body.
type APITaskRule struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	OperationType  string            `json:"operationType"`
	OperationCode  string            `json:"operationCode"`
	RuleDefinition APITaskRuleDefinition `json:"ruleDefinition"`
	IsDefault      bool              `json:"isDefault"`
	Created        time.Time         `json:"created"`
	Updated        time.Time         `json:"updated"`
}

// APITaskRuleDefinition is the executable body of a rule. The shape matches
// flow/internal/task/operationrules.RuleDefinition exactly so we can
// unmarshal Flow's RuleDefinitionJson straight into it.
type APITaskRuleDefinition struct {
	Version string            `json:"version"`
	Steps   []APITaskRuleSequenceStep `json:"steps,omitempty"`
}

// APITaskRuleSequenceStep mirrors operationrules.SequenceStep. Durations are kept as
// strings (Go duration syntax, e.g. "30s", "2m") so the round-trip with Flow
// preserves the exact form the user authored and Flow does the parsing.
type APITaskRuleSequenceStep struct {
	ComponentType string            `json:"component_type"`
	Stage         int               `json:"stage"`
	MaxParallel   int               `json:"max_parallel"`
	Timeout       string            `json:"timeout,omitempty"`
	Retry         *APITaskRuleRetryPolicy   `json:"retry,omitempty"`
	PreOperation  []APITaskRuleActionConfig `json:"pre_operation,omitempty"`
	MainOperation APITaskRuleActionConfig   `json:"main_operation"`
	PostOperation []APITaskRuleActionConfig `json:"post_operation,omitempty"`
	DelayAfter    string            `json:"delay_after,omitempty"`
}

// APITaskRuleActionConfig mirrors operationrules.ActionConfig.
type APITaskRuleActionConfig struct {
	Name         string         `json:"name"`
	Timeout      string         `json:"timeout,omitempty"`
	PollInterval string         `json:"poll_interval,omitempty"`
	Parameters   map[string]any `json:"parameters,omitempty"`
}

// APITaskRuleRetryPolicy mirrors operationrules.RetryPolicy.
type APITaskRuleRetryPolicy struct {
	MaxAttempts        int     `json:"max_attempts"`
	InitialInterval    string  `json:"initial_interval"`
	BackoffCoefficient float64 `json:"backoff_coefficient"`
	MaxInterval        string  `json:"max_interval,omitempty"`
}

// FromProto populates an APITaskRule from a Flow protobuf OperationRule.
// Returns an error if ruleDefinitionJson cannot be unmarshaled into the API
// schema (this should never happen for rules that were written by Flow itself).
func (r *APITaskRule) FromProto(pbRule *flowv1.OperationRule) error {
	if pbRule == nil {
		return nil
	}
	if pbRule.GetId() != nil {
		r.ID = pbRule.GetId().GetId()
	}
	r.Name = pbRule.GetName()
	r.Description = pbRule.GetDescription()
	r.OperationType = enumOr(ProtoToAPIOperationTypeName, pbRule.GetOperationType(), "")
	r.OperationCode = pbRule.GetOperationCode()
	r.IsDefault = pbRule.GetIsDefault()
	if ts := pbRule.GetCreatedAt(); ts != nil {
		r.Created = ts.AsTime().UTC()
	}
	if ts := pbRule.GetUpdatedAt(); ts != nil {
		r.Updated = ts.AsTime().UTC()
	}

	if raw := pbRule.GetRuleDefinitionJson(); raw != "" {
		if err := json.Unmarshal([]byte(raw), &r.RuleDefinition); err != nil {
			return fmt.Errorf("invalid ruleDefinition from Flow: %w", err)
		}
	}
	return nil
}

// NewAPITaskRule constructs an APITaskRule from a Flow proto rule.
func NewAPITaskRule(pbRule *flowv1.OperationRule) (*APITaskRule, error) {
	r := &APITaskRule{}
	if err := r.FromProto(pbRule); err != nil {
		return nil, err
	}
	return r, nil
}

// ~~~~~ Create ~~~~~ //

// APITaskRuleCreateRequest is the JSON body for POST /rule.
//
// IsDefault is intentionally absent: rules are created as non-default and
// promoted to default via a dedicated path (not exposed in this MVP). See the
// rule API design doc for the rationale (atomic swap requires Flow's
// SetRuleAsDefault RPC, which has different semantics than CRUD update).
type APITaskRuleCreateRequest struct {
	SiteID         string            `json:"siteId"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	OperationType  string            `json:"operationType"`
	OperationCode  string            `json:"operationCode"`
	RuleDefinition APITaskRuleDefinition `json:"ruleDefinition"`
}

// Validate runs basic shape validation. Deep validation (operation code
// membership, rule definition semantics) lives in Flow and is surfaced via
// the workflow error path; doing it again here would force the API layer to
// track Flow's evolving allow-list.
func (r *APITaskRuleCreateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.OperationType == "" {
		return fmt.Errorf("operationType is required")
	}
	if _, err := operationTypeFromAPI(r.OperationType); err != nil {
		return err
	}
	if r.OperationCode == "" {
		return fmt.Errorf("operationCode is required")
	}
	return nil
}

// ToProto converts the request into the Flow CreateOperationRuleRequest.
// Returns an error if the rule definition cannot be marshaled (shouldn't
// happen for well-formed input).
func (r *APITaskRuleCreateRequest) ToProto() (*flowv1.CreateOperationRuleRequest, error) {
	opType, err := operationTypeFromAPI(r.OperationType)
	if err != nil {
		return nil, err
	}
	rdJSON, err := json.Marshal(r.RuleDefinition)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ruleDefinition: %w", err)
	}
	return &flowv1.CreateOperationRuleRequest{
		Name:               r.Name,
		Description:        r.Description,
		OperationType:      opType,
		OperationCode:      r.OperationCode,
		RuleDefinitionJson: string(rdJSON),
	}, nil
}

// ~~~~~ Update ~~~~~ //

// APITaskRuleUpdateRequest is the JSON body for PATCH /rule/{id}.
//
// All mutable fields are optional pointers so unset means "leave unchanged".
// operationType / operationCode are intentionally immutable after creation
// (mirroring Flow's UpdateTaskRule constraint) — change them by creating a new
// rule and deleting the old one. is_default is also immutable here; see
// APITaskRuleCreateRequest comment.
type APITaskRuleUpdateRequest struct {
	SiteID         string             `json:"siteId"`
	Name           *string            `json:"name,omitempty"`
	Description    *string            `json:"description,omitempty"`
	RuleDefinition *APITaskRuleDefinition `json:"ruleDefinition,omitempty"`
}

// Validate enforces that the request actually carries at least one field to
// update. siteId is always required as it routes to the right Flow.
func (r *APITaskRuleUpdateRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId is required")
	}
	if r.Name == nil && r.Description == nil && r.RuleDefinition == nil {
		return fmt.Errorf("at least one of name, description, ruleDefinition must be provided")
	}
	if r.Name != nil && *r.Name == "" {
		return fmt.Errorf("name cannot be empty when provided")
	}
	return nil
}

// ToProto converts the update request into the Flow UpdateOperationRuleRequest.
// ruleID is the path parameter from the request URL.
func (r *APITaskRuleUpdateRequest) ToProto(ruleID string) (*flowv1.UpdateOperationRuleRequest, error) {
	req := &flowv1.UpdateOperationRuleRequest{
		RuleId:      &flowv1.UUID{Id: ruleID},
		Name:        r.Name,
		Description: r.Description,
	}
	if r.RuleDefinition != nil {
		rdJSON, err := json.Marshal(r.RuleDefinition)
		if err != nil {
			return nil, fmt.Errorf("failed to encode ruleDefinition: %w", err)
		}
		s := string(rdJSON)
		req.RuleDefinitionJson = &s
	}
	return req, nil
}

// ~~~~~ Get / Delete (siteId via query) ~~~~~ //

// APITaskRuleGetRequest captures query parameters for GET /rule/{id}.
type APITaskRuleGetRequest struct {
	SiteID string `query:"siteId"`
}

func (r *APITaskRuleGetRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId query parameter is required")
	}
	return nil
}

// APITaskRuleDeleteRequest captures query parameters for DELETE /rule/{id}.
type APITaskRuleDeleteRequest struct {
	SiteID string `query:"siteId"`
}

func (r *APITaskRuleDeleteRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId query parameter is required")
	}
	return nil
}

// ~~~~~ List ~~~~~ //

// APITaskRuleGetAllRequest binds query parameters for GET /rule. Pagination is
// bound separately via pagination.PageRequest.
type APITaskRuleGetAllRequest struct {
	SiteID        string `query:"siteId"`
	OperationType string `query:"operationType"`
}

func (r *APITaskRuleGetAllRequest) Validate() error {
	if r.SiteID == "" {
		return fmt.Errorf("siteId query parameter is required")
	}
	if _, err := operationTypeFromAPI(r.OperationType); err != nil {
		return err
	}
	return nil
}

// ToProto converts the list filters into the Flow ListOperationRulesRequest.
// Returns an error if operationType is invalid.
func (r *APITaskRuleGetAllRequest) ToProto(page pagination.PageRequest) (*flowv1.ListOperationRulesRequest, error) {
	req := &flowv1.ListOperationRulesRequest{}
	if r.OperationType != "" {
		opType, err := operationTypeFromAPI(r.OperationType)
		if err != nil {
			return nil, err
		}
		req.OperationType = &opType
	}
	if page.PageSize != nil && *page.PageSize > 0 {
		limit := int32(*page.PageSize)
		req.Limit = &limit
	}
	// Flow uses offset-based pagination. Translate (pageNumber, pageSize) into
	// offset; this matches how task list pagination flows through Flow.
	if page.PageNumber != nil && page.PageSize != nil && *page.PageNumber > 0 && *page.PageSize > 0 {
		offset := int32((*page.PageNumber - 1) * (*page.PageSize))
		req.Offset = &offset
	}
	return req, nil
}

// QueryValues returns query parameters that participate in deterministic
// workflow ID hashing, including pagination fields so concurrent requests for
// different filters/pages do not reuse the same workflow execution.
func (r *APITaskRuleGetAllRequest) QueryValues(page pagination.PageRequest) url.Values {
	v := url.Values{}
	v.Set("siteId", r.SiteID)
	if r.OperationType != "" {
		v.Set("operationType", r.OperationType)
	}
	if page.PageNumber != nil && *page.PageNumber != 0 {
		v.Set("pageNumber", strconv.Itoa(*page.PageNumber))
	}
	if page.PageSize != nil && *page.PageSize != 0 {
		v.Set("pageSize", strconv.Itoa(*page.PageSize))
	}
	return v
}
