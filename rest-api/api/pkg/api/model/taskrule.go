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

// APIOperationType is the operationType field of an Operation Rule.
type APIOperationType string

const (
	APIOperationTypePowerControl    APIOperationType = "PowerControl"
	APIOperationTypeFirmwareControl APIOperationType = "FirmwareControl"
)

// validOperationTypes lists the supported APIOperationType values.
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

var protoToAPIOperationType = map[flowv1.OperationType]APIOperationType{
	flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL:    APIOperationTypePowerControl,
	flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL: APIOperationTypeFirmwareControl,
}

var apiToProtoOperationType = map[APIOperationType]flowv1.OperationType{
	APIOperationTypePowerControl:    flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
	APIOperationTypeFirmwareControl: flowv1.OperationType_OPERATION_TYPE_FIRMWARE_CONTROL,
}

// ToProto converts to Flow's protobuf OperationType. The empty value maps
// to OPERATION_TYPE_UNKNOWN; any unrecognized value returns an error.
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

// APITaskRule is the API response model for an Operation Rule.
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

// APITaskRuleSequenceStep describes one stage of execution. Duration fields
// (Timeout, DelayAfter) are Go duration strings (e.g. "30s", "2m") parsed by
// Flow.
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

// APITaskRuleActionConfig configures a single action within a step.
// Parameters is action-specific and passes through to Flow unchanged.
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

// proto* types mirror their APITaskRule* counterparts with snake_case JSON
// tags for (de)serializing Flow's rule_definition_json blob. Keep each in
// lock-step with its API counterpart when adding fields.
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

func (d *APITaskRuleDefinition) FromProto(p protoRuleDefinition) {
	d.Version = p.Version
	if p.Steps != nil {
		d.Steps = make([]APITaskRuleSequenceStep, len(p.Steps))
		for i, s := range p.Steps {
			d.Steps[i].FromProto(s)
		}
	}
}

func (s *APITaskRuleSequenceStep) FromProto(p protoSequenceStep) {
	s.ComponentType = p.ComponentType
	s.Stage = p.Stage
	s.MaxParallel = p.MaxParallel
	s.Timeout = p.Timeout
	s.MainOperation.FromProto(p.MainOperation)
	s.DelayAfter = p.DelayAfter
	if p.Retry != nil {
		var rp APITaskRuleRetryPolicy
		rp.FromProto(*p.Retry)
		s.Retry = &rp
	}
	if p.PreOperation != nil {
		s.PreOperation = make([]APITaskRuleActionConfig, len(p.PreOperation))
		for i, a := range p.PreOperation {
			s.PreOperation[i].FromProto(a)
		}
	}
	if p.PostOperation != nil {
		s.PostOperation = make([]APITaskRuleActionConfig, len(p.PostOperation))
		for i, a := range p.PostOperation {
			s.PostOperation[i].FromProto(a)
		}
	}
}

func (a *APITaskRuleActionConfig) FromProto(p protoActionConfig) {
	a.Name = p.Name
	a.Timeout = p.Timeout
	a.PollInterval = p.PollInterval
	a.Parameters = p.Parameters
}

func (rp *APITaskRuleRetryPolicy) FromProto(p protoRetryPolicy) {
	rp.MaxAttempts = p.MaxAttempts
	rp.InitialInterval = p.InitialInterval
	rp.BackoffCoefficient = p.BackoffCoefficient
	rp.MaxInterval = p.MaxInterval
}

// toFlowJSON encodes the rule definition into Flow's rule_definition_json
// blob (snake_case JSON).
func (d APITaskRuleDefinition) toFlowJSON() (string, error) {
	raw, err := json.Marshal(d.toProto())
	if err != nil {
		return "", fmt.Errorf("failed to encode ruleDefinition: %w", err)
	}
	return string(raw), nil
}

// ruleDefinitionFromFlowJSON decodes Flow's rule_definition_json blob into
// an APITaskRuleDefinition.
func ruleDefinitionFromFlowJSON(raw string) (APITaskRuleDefinition, error) {
	var p protoRuleDefinition
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return APITaskRuleDefinition{}, fmt.Errorf("invalid ruleDefinition from Flow: %w", err)
	}
	var d APITaskRuleDefinition
	d.FromProto(p)
	return d, nil
}

// FromProto populates an APITaskRule from a Flow protobuf OperationRule.
// Returns an error if ruleDefinitionJson cannot be unmarshaled.
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
		def, err := ruleDefinitionFromFlowJSON(raw)
		if err != nil {
			return err
		}
		r.RuleDefinition = def
	}
	return nil
}

// ~~~~~ Create ~~~~~ //

// APITaskRuleCreateRequest is the JSON body for POST /rule. isDefault is
// not accepted — rules are created non-default; promotion uses Flow's
// SetRuleAsDefault RPC, which is not surfaced through this CRUD API.
type APITaskRuleCreateRequest struct {
	SiteID         string                `json:"siteId"`
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	OperationType  APIOperationType      `json:"operationType"`
	OperationCode  string                `json:"operationCode"`
	RuleDefinition APITaskRuleDefinition `json:"ruleDefinition"`
}

// Validate enforces shape only; semantic checks (operation code membership,
// rule definition correctness) are performed by Flow.
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
func (r *APITaskRuleCreateRequest) ToProto() (*flowv1.CreateOperationRuleRequest, error) {
	opType, err := r.OperationType.ToProto()
	if err != nil {
		return nil, err
	}
	rdJSON, err := r.RuleDefinition.toFlowJSON()
	if err != nil {
		return nil, err
	}
	return &flowv1.CreateOperationRuleRequest{
		Name:               r.Name,
		Description:        r.Description,
		OperationType:      opType,
		OperationCode:      r.OperationCode,
		RuleDefinitionJson: rdJSON,
	}, nil
}

// ~~~~~ Update ~~~~~ //

// APITaskRuleUpdateRequest is the JSON body for PATCH /rule/{id}. Nil
// pointer fields mean "leave unchanged". operationType, operationCode, and
// isDefault are immutable after creation and not exposed here.
type APITaskRuleUpdateRequest struct {
	SiteID         string                 `json:"siteId"`
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	RuleDefinition *APITaskRuleDefinition `json:"ruleDefinition"`
}

// Validate enforces that the request carries at least one mutable field.
func (r *APITaskRuleUpdateRequest) Validate() error {
	err := validation.ValidateStruct(r,
		validation.Field(&r.SiteID, validation.Required.Error("siteId is required")),
		validation.Field(&r.Name,
			validation.When(r.Name != nil,
				validation.Required.Error("name cannot be empty when provided"))),
	)
	if err != nil {
		return err
	}
	if r.Name == nil && r.Description == nil && r.RuleDefinition == nil {
		return fmt.Errorf("at least one of name, description, ruleDefinition must be provided")
	}
	return nil
}

// ToProto converts the update request into the Flow UpdateOperationRuleRequest.
func (r *APITaskRuleUpdateRequest) ToProto(ruleID string) (*flowv1.UpdateOperationRuleRequest, error) {
	req := &flowv1.UpdateOperationRuleRequest{
		RuleId:      &flowv1.UUID{Id: ruleID},
		Name:        r.Name,
		Description: r.Description,
	}
	if r.RuleDefinition != nil {
		rdJSON, err := r.RuleDefinition.toFlowJSON()
		if err != nil {
			return nil, err
		}
		req.RuleDefinitionJson = &rdJSON
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
	// Flow uses offset-based pagination; translate (pageNumber, pageSize).
	if page.PageNumber != nil && page.PageSize != nil && *page.PageNumber > 0 && *page.PageSize > 0 {
		offset := int32((*page.PageNumber - 1) * (*page.PageSize))
		req.Offset = &offset
	}
	return req, nil
}

// QueryValues returns the request fields that feed the workflow ID hash,
// including pagination so different pages map to distinct workflow IDs.
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
