// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// APIOperationType is the REST surface enum for operation types. PascalCase
// values follow the convention used by other enum-like strings in this
// package (TaskStatus, ComponentType, DiffType, BMCType). Flow's stored
// rule files keep their snake_case spelling; conversion happens at the
// boundary via (APIOperationType).ToProto and the protoToAPIOperationType map.
type APIOperationType string

const (
	APIOperationTypePowerControl    APIOperationType = "PowerControl"
	APIOperationTypeFirmwareControl APIOperationType = "FirmwareControl"
)

// validOperationTypes lists the supported values; consumed by validation.In
// on every request model that accepts operationType.
var validOperationTypes = []APIOperationType{
	APIOperationTypePowerControl,
	APIOperationTypeFirmwareControl,
}

var validOperationTypesAny = func() []any {
	out := make([]any, len(validOperationTypes))
	for i, t := range validOperationTypes {
		out[i] = t
	}
	return out
}()

// protoToAPIOperationType maps Flow's protobuf enum to the REST string form.
var protoToAPIOperationType = map[flowv1.OperationType]APIOperationType{
	flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL:    APIOperationTypePowerControl,
	flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL: APIOperationTypeFirmwareControl,
}

var apiToProtoOperationType = map[APIOperationType]flowv1.OperationType{
	APIOperationTypePowerControl:    flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
	APIOperationTypeFirmwareControl: flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL,
}

// ToProto converts to Flow's protobuf OperationType. The empty value maps
// to OPERATION_TYPE_UNKNOWN (caller decides whether that is acceptable);
// any other unknown value is an error so we don't silently forward garbage.
func (t APIOperationType) ToProto() (flowv1.OperationType, error) {
	if t == "" {
		return flowv1.OperationType_OPERATION_TYPE_UNKNOWN, nil
	}
	v, ok := apiToProtoOperationType[t]
	if !ok {
		return flowv1.OperationType_OPERATION_TYPE_UNKNOWN,
			fmt.Errorf("invalid operationType %q (expected one of %v)", t, validOperationTypes)
	}
	return v, nil
}

// APITaskRule is the API response model for an Operation Rule. All keys
// use camelCase per the REST convention applied throughout this package.
// Conversion to Flow's snake_case rule_definition_json blob happens in
// (*APITaskRule).FromProto and (*APITaskRuleCreateRequest).ToProto via the
// proto* mirror types and their toProto / toAPI methods below.
type APITaskRule struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	OperationType  APIOperationType      `json:"operationType"`
	OperationCode  string                `json:"operationCode"`
	RuleDefinition APITaskRuleDefinition `json:"ruleDefinition"`
	IsDefault      bool                  `json:"isDefault"`
	Created        time.Time             `json:"created"`
	Updated        time.Time             `json:"updated"`
}

// APITaskRuleDefinition is the executable body of a rule.
type APITaskRuleDefinition struct {
	Version string                    `json:"version"`
	Steps   []APITaskRuleSequenceStep `json:"steps"`
}

// APITaskRuleSequenceStep describes one stage of execution. Durations are
// kept as strings (Go duration syntax, e.g. "30s", "2m") so the round-trip
// with Flow preserves the exact form the user authored and Flow does the
// parsing.
type APITaskRuleSequenceStep struct {
	ComponentType string                    `json:"componentType"`
	Stage         int                       `json:"stage"`
	MaxParallel   int                       `json:"maxParallel"`
	Timeout       string                    `json:"timeout"`
	Retry         *APITaskRuleRetryPolicy   `json:"retry"`
	PreOperation  []APITaskRuleActionConfig `json:"preOperation"`
	MainOperation APITaskRuleActionConfig   `json:"mainOperation"`
	PostOperation []APITaskRuleActionConfig `json:"postOperation"`
	DelayAfter    string                    `json:"delayAfter"`
}

// APITaskRuleActionConfig configures a single action within a step. The
// `parameters` map is intentionally free-form: keys and values are action-
// specific and pass through to Flow's executor unchanged.
type APITaskRuleActionConfig struct {
	Name         string         `json:"name"`
	Timeout      string         `json:"timeout"`
	PollInterval string         `json:"pollInterval"`
	Parameters   map[string]any `json:"parameters"`
}

// APITaskRuleRetryPolicy describes retry behavior for a step's workflow.
type APITaskRuleRetryPolicy struct {
	MaxAttempts        int     `json:"maxAttempts"`
	InitialInterval    string  `json:"initialInterval"`
	BackoffCoefficient float64 `json:"backoffCoefficient"`
	MaxInterval        string  `json:"maxInterval"`
}

// proto* types mirror the API-facing rule definition structs above but carry
// snake_case JSON tags so they (de)serialize directly to and from Flow's
// rule_definition_json blob — which uses the same shape Flow's protobuf
// definitions would have if the rule body were modeled in proto today. Keep
// each proto* type in lock-step with its API counterpart when adding fields.
type protoRuleDefinition struct {
	Version string              `json:"version"`
	Steps   []protoSequenceStep `json:"steps,omitempty"`
}

type protoSequenceStep struct {
	ComponentType string              `json:"component_type"`
	Stage         int                 `json:"stage"`
	MaxParallel   int                 `json:"max_parallel"`
	Timeout       string              `json:"timeout,omitempty"`
	Retry         *protoRetryPolicy   `json:"retry,omitempty"`
	PreOperation  []protoActionConfig `json:"pre_operation,omitempty"`
	MainOperation protoActionConfig   `json:"main_operation"`
	PostOperation []protoActionConfig `json:"post_operation,omitempty"`
	DelayAfter    string              `json:"delay_after,omitempty"`
}

type protoActionConfig struct {
	Name         string         `json:"name"`
	Timeout      string         `json:"timeout,omitempty"`
	PollInterval string         `json:"poll_interval,omitempty"`
	Parameters   map[string]any `json:"parameters,omitempty"`
}

type protoRetryPolicy struct {
	MaxAttempts        int     `json:"max_attempts"`
	InitialInterval    string  `json:"initial_interval"`
	BackoffCoefficient float64 `json:"backoff_coefficient"`
	MaxInterval        string  `json:"max_interval,omitempty"`
}

// API → proto conversions.

func (d APITaskRuleDefinition) toProto() protoRuleDefinition {
	out := protoRuleDefinition{Version: d.Version}
	if d.Steps != nil {
		out.Steps = make([]protoSequenceStep, len(d.Steps))
		for i, s := range d.Steps {
			out.Steps[i] = s.toProto()
		}
	}
	return out
}

func (s APITaskRuleSequenceStep) toProto() protoSequenceStep {
	out := protoSequenceStep{
		ComponentType: s.ComponentType,
		Stage:         s.Stage,
		MaxParallel:   s.MaxParallel,
		Timeout:       s.Timeout,
		MainOperation: s.MainOperation.toProto(),
		DelayAfter:    s.DelayAfter,
	}
	if s.Retry != nil {
		p := s.Retry.toProto()
		out.Retry = &p
	}
	if s.PreOperation != nil {
		out.PreOperation = make([]protoActionConfig, len(s.PreOperation))
		for i, a := range s.PreOperation {
			out.PreOperation[i] = a.toProto()
		}
	}
	if s.PostOperation != nil {
		out.PostOperation = make([]protoActionConfig, len(s.PostOperation))
		for i, a := range s.PostOperation {
			out.PostOperation[i] = a.toProto()
		}
	}
	return out
}

func (ac APITaskRuleActionConfig) toProto() protoActionConfig {
	return protoActionConfig{
		Name:         ac.Name,
		Timeout:      ac.Timeout,
		PollInterval: ac.PollInterval,
		Parameters:   ac.Parameters,
	}
}

func (rp APITaskRuleRetryPolicy) toProto() protoRetryPolicy {
	return protoRetryPolicy{
		MaxAttempts:        rp.MaxAttempts,
		InitialInterval:    rp.InitialInterval,
		BackoffCoefficient: rp.BackoffCoefficient,
		MaxInterval:        rp.MaxInterval,
	}
}

// proto → API conversions.

func (p protoRuleDefinition) toAPI() APITaskRuleDefinition {
	out := APITaskRuleDefinition{Version: p.Version}
	if p.Steps != nil {
		out.Steps = make([]APITaskRuleSequenceStep, len(p.Steps))
		for i, s := range p.Steps {
			out.Steps[i] = s.toAPI()
		}
	}
	return out
}

func (p protoSequenceStep) toAPI() APITaskRuleSequenceStep {
	out := APITaskRuleSequenceStep{
		ComponentType: p.ComponentType,
		Stage:         p.Stage,
		MaxParallel:   p.MaxParallel,
		Timeout:       p.Timeout,
		MainOperation: p.MainOperation.toAPI(),
		DelayAfter:    p.DelayAfter,
	}
	if p.Retry != nil {
		a := p.Retry.toAPI()
		out.Retry = &a
	}
	if p.PreOperation != nil {
		out.PreOperation = make([]APITaskRuleActionConfig, len(p.PreOperation))
		for i, a := range p.PreOperation {
			out.PreOperation[i] = a.toAPI()
		}
	}
	if p.PostOperation != nil {
		out.PostOperation = make([]APITaskRuleActionConfig, len(p.PostOperation))
		for i, a := range p.PostOperation {
			out.PostOperation[i] = a.toAPI()
		}
	}
	return out
}

func (p protoActionConfig) toAPI() APITaskRuleActionConfig {
	return APITaskRuleActionConfig{
		Name:         p.Name,
		Timeout:      p.Timeout,
		PollInterval: p.PollInterval,
		Parameters:   p.Parameters,
	}
}

func (p protoRetryPolicy) toAPI() APITaskRuleRetryPolicy {
	return APITaskRuleRetryPolicy{
		MaxAttempts:        p.MaxAttempts,
		InitialInterval:    p.InitialInterval,
		BackoffCoefficient: p.BackoffCoefficient,
		MaxInterval:        p.MaxInterval,
	}
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
	r.OperationType = enumOr(protoToAPIOperationType, pbRule.GetOperationType(), "")
	r.OperationCode = pbRule.GetOperationCode()
	r.IsDefault = pbRule.GetIsDefault()
	if ts := pbRule.GetCreatedAt(); ts != nil {
		r.Created = ts.AsTime().UTC()
	}
	if ts := pbRule.GetUpdatedAt(); ts != nil {
		r.Updated = ts.AsTime().UTC()
	}

	if raw := pbRule.GetRuleDefinitionJson(); raw != "" {
		var p protoRuleDefinition
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return fmt.Errorf("invalid ruleDefinition from Flow: %w", err)
		}
		r.RuleDefinition = p.toAPI()
	}
	return nil
}

// ~~~~~ Create ~~~~~ //

// APITaskRuleCreateRequest is the JSON body for POST /rule.
//
// IsDefault is intentionally absent: rules are created as non-default and
// promoted to default via a dedicated path (not surfaced through this CRUD
// API). See the rule API design doc for the rationale — the atomic swap
// requires Flow's SetRuleAsDefault RPC, which has different semantics than a
// CRUD update.
type APITaskRuleCreateRequest struct {
	SiteID         string                `json:"siteId"`
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	OperationType  APIOperationType      `json:"operationType"`
	OperationCode  string                `json:"operationCode"`
	RuleDefinition APITaskRuleDefinition `json:"ruleDefinition"`
}

// Validate runs basic shape validation. Deep validation (operation code
// membership, rule definition semantics) lives in Flow and is surfaced via
// the workflow error path; doing it again here would force the API layer to
// track Flow's evolving allow-list.
func (r *APITaskRuleCreateRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.Name, validation.Required.Error("name is required")),
		validation.Field(&r.OperationType,
			validation.Required.Error("operationType is required"),
			validation.In(validOperationTypesAny...).Error(
				fmt.Sprintf("operationType must be one of %v", validOperationTypes))),
		validation.Field(&r.OperationCode, validation.Required.Error("operationCode is required")),
	)
}

// ToProto converts the request into the Flow CreateOperationRuleRequest.
// Returns an error if the rule definition cannot be marshaled (shouldn't
// happen for well-formed input).
func (r *APITaskRuleCreateRequest) ToProto() (*flowv1.CreateOperationRuleRequest, error) {
	opType, err := r.OperationType.ToProto()
	if err != nil {
		return nil, err
	}
	rdJSON, err := json.Marshal(r.RuleDefinition.toProto())
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
	SiteID         string                 `json:"siteId"`
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	RuleDefinition *APITaskRuleDefinition `json:"ruleDefinition"`
}

// Validate enforces that the request actually carries at least one field to
// update. siteId is always required as it routes to the right Flow.
func (r *APITaskRuleUpdateRequest) Validate() error {
	if err := validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.Name,
			validation.When(r.Name != nil,
				validation.Required.Error("name cannot be empty when provided"))),
	); err != nil {
		return err
	}
	if r.Name == nil && r.Description == nil && r.RuleDefinition == nil {
		return fmt.Errorf("at least one of name, description, ruleDefinition must be provided")
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
		rdJSON, err := json.Marshal(r.RuleDefinition.toProto())
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
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
	)
}

// APITaskRuleDeleteRequest captures query parameters for DELETE /rule/{id}.
type APITaskRuleDeleteRequest struct {
	SiteID string `query:"siteId"`
}

func (r *APITaskRuleDeleteRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
	)
}

// ~~~~~ List ~~~~~ //

// APITaskRuleGetAllRequest binds query parameters for GET /rule. Pagination is
// bound separately via pagination.PageRequest.
type APITaskRuleGetAllRequest struct {
	SiteID        string           `query:"siteId"`
	OperationType APIOperationType `query:"operationType"`
}

func (r *APITaskRuleGetAllRequest) Validate() error {
	return validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId query parameter is required")),
		validation.Field(&r.OperationType,
			validation.When(r.OperationType != "",
				validation.In(validOperationTypesAny...).Error(
					fmt.Sprintf("operationType must be one of %v", validOperationTypes)))),
	)
}

// ToProto converts the list filters into the Flow ListOperationRulesRequest.
// Returns an error if operationType is invalid.
func (r *APITaskRuleGetAllRequest) ToProto(page pagination.PageRequest) (*flowv1.ListOperationRulesRequest, error) {
	req := &flowv1.ListOperationRulesRequest{}
	if r.OperationType != "" {
		opType, err := r.OperationType.ToProto()
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
