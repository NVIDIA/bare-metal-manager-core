// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	hutil "github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	validationis "github.com/go-ozzo/ozzo-validation/v4/is"
)

const MaxNetworkSecurityGroupRules = 200
const NetworkSecurityGroupRulePriorityMin = 0
const NetworkSecurityGroupRulePriorityMax = 60000

// Action conversion maps

const APINetworkSecurityGroupRuleActionPermit = "PERMIT"
const APINetworkSecurityGroupRuleActionDeny = "DENY"

var NetworkSecurityGroupRuleProtobufActionFromAPIAction = map[string]cwssaws.NetworkSecurityGroupRuleAction{
	APINetworkSecurityGroupRuleActionPermit: cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_PERMIT,
	APINetworkSecurityGroupRuleActionDeny:   cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_DENY,
}

var NetworkSecurityGroupRuleAPIActionFromProtobufAction = map[cwssaws.NetworkSecurityGroupRuleAction]string{
	cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_PERMIT: APINetworkSecurityGroupRuleActionPermit,
	cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_DENY:   APINetworkSecurityGroupRuleActionDeny,
}

// Direction conversion maps

const APINetworkSecurityGroupRuleDirectionIngress = "INGRESS"
const APINetworkSecurityGroupRuleActionEgress = "EGRESS"

var NetworkSecurityGroupRuleProtobufDirectionFromAPIDirection = map[string]cwssaws.NetworkSecurityGroupRuleDirection{
	APINetworkSecurityGroupRuleDirectionIngress: cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INGRESS,
	APINetworkSecurityGroupRuleActionEgress:     cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_EGRESS,
}

var NetworkSecurityGroupRuleAPIDirectionFromProtobufDirection = map[cwssaws.NetworkSecurityGroupRuleDirection]string{
	cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INGRESS: APINetworkSecurityGroupRuleDirectionIngress,
	cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_EGRESS:  APINetworkSecurityGroupRuleActionEgress,
}

// Protocol conversion maps

const APINetworkSecurityGroupRuleProtocolAny = "ANY"
const APINetworkSecurityGroupRuleProtocolIcmp = "ICMP"
const APINetworkSecurityGroupRuleProtocolIcmp6 = "ICMP6"
const APINetworkSecurityGroupRuleProtocolTcp = "TCP"
const APINetworkSecurityGroupRuleProtocolUdp = "UDP"

var NetworkSecurityGroupRuleProtobufProtocolFromAPIProtocol = map[string]cwssaws.NetworkSecurityGroupRuleProtocol{
	APINetworkSecurityGroupRuleProtocolAny:   cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ANY,
	APINetworkSecurityGroupRuleProtocolIcmp:  cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP,
	APINetworkSecurityGroupRuleProtocolIcmp6: cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP6,
	APINetworkSecurityGroupRuleProtocolTcp:   cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_TCP,
	APINetworkSecurityGroupRuleProtocolUdp:   cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_UDP,
}

var NetworkSecurityGroupRuleAPIProtocolFromProtobufProtocol = map[cwssaws.NetworkSecurityGroupRuleProtocol]string{
	cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ANY:   APINetworkSecurityGroupRuleProtocolAny,
	cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP:  APINetworkSecurityGroupRuleProtocolIcmp,
	cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP6: APINetworkSecurityGroupRuleProtocolIcmp6,
	cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_TCP:   APINetworkSecurityGroupRuleProtocolTcp,
	cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_UDP:   APINetworkSecurityGroupRuleProtocolUdp,
}

// Propagation status maps

const APINetworkSecurityGroupPropagationDetailedStatusNone = "None"
const APINetworkSecurityGroupPropagationDetailedStatusPartial = "Partial"
const APINetworkSecurityGroupPropagationDetailedStatusFull = "Full"
const APINetworkSecurityGroupPropagationDetailedStatusUnknown = "Unknown"
const APINetworkSecurityGroupPropagationDetailedStatusError = "Error"

var NetworkSecurityGroupRuleAPIPropagationDetailedStatusFromProtobufPropagationStatus = map[cwssaws.NetworkSecurityGroupPropagationStatus]string{
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_NONE:    APINetworkSecurityGroupPropagationDetailedStatusNone,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_PARTIAL: APINetworkSecurityGroupPropagationDetailedStatusPartial,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_FULL:    APINetworkSecurityGroupPropagationDetailedStatusFull,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_UNKNOWN: APINetworkSecurityGroupPropagationDetailedStatusUnknown,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_ERROR:   APINetworkSecurityGroupPropagationDetailedStatusError,
}

const APINetworkSecurityGroupPropagationStatusError = "Error"
const APINetworkSecurityGroupPropagationStatusSynchronizing = "Synchronizing"
const APINetworkSecurityGroupPropagationStatusSynchronized = "Synchronized"

var NetworkSecurityGroupRuleAPIPropagationStatusFromProtobufPropagationStatus = map[cwssaws.NetworkSecurityGroupPropagationStatus]string{
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_NONE:    APINetworkSecurityGroupPropagationStatusSynchronizing,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_PARTIAL: APINetworkSecurityGroupPropagationStatusSynchronizing,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_FULL:    APINetworkSecurityGroupPropagationStatusSynchronized,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_UNKNOWN: APINetworkSecurityGroupPropagationStatusError,
	cwssaws.NetworkSecurityGroupPropagationStatus_NSG_PROP_STATUS_ERROR:   APINetworkSecurityGroupPropagationStatusError,
}

// APINetworkSecurityGroupCreateRequest is the data structure to capture instance request to create a new NetworkSecurityGroup
type APINetworkSecurityGroupCreateRequest struct {
	// Name is the name of the NetworkSecurityGroup
	Name string `json:"name"`
	// Description is the description of the NetworkSecurityGroup
	Description *string `json:"description"`
	// SiteID is the ID of the Site
	SiteID string `json:"siteId"`
	// Rules is the list of NetworkSecurityGroupRuleAttributes for the NetworkSecurityGroup
	Rules []APINetworkSecurityGroupRule `json:"rules"`
	// StatefulEgress defines whether a NetworkSecurityGroup's egress rules will be automatically stateful
	StatefulEgress bool `json:"statefulEgress"`
	// Labels to be associted with the NetworkSecurityGroup
	Labels map[string]string `json:"labels"`
}

// Validate ensures the values in the request are acceptable
func (req APINetworkSecurityGroupCreateRequest) Validate(siteConfig *cdbm.SiteConfig) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required.Error(validationErrorStringLength),
			validation.By(util.ValidateNameCharacters),
			validation.Length(2, 256).Error(validationErrorStringLength)),
		validation.Field(&req.SiteID,
			validation.Required.Error(validationErrorValueRequired),
			validationis.UUID.Error(validationErrorInvalidUUID)),
		validation.Field(&req.Description,
			validation.When(req.Description != nil, validation.Length(0, 1024).Error(validationErrorDescriptionStringLength)),
		),
	)
	if err != nil {
		return err
	}

	maxRules := MaxNetworkSecurityGroupRules
	if siteConfig != nil && siteConfig.MaxNetworkSecurityGroupRuleCount != nil {
		maxRules = *siteConfig.MaxNetworkSecurityGroupRuleCount
	}

	if len(req.Rules) > maxRules {
		return validation.Errors{
			"rules": fmt.Errorf("number of rules cannot exceed %d", maxRules),
		}
	}

	// Individual rule validation happens later during
	// processing when we convert from request rules to
	// the protobuf representation.

	if err := util.ValidateLabels(req.Labels); err != nil {
		return err
	}

	return nil
}

// APINetworkSecurityGroupUpdateRequest is the data structure to capture user request to update a NetworkSecurityGroup
type APINetworkSecurityGroupUpdateRequest struct {
	// Name is the name of the NetworkSecurityGroup
	Name *string `json:"name"`
	// Description is the description of the NetworkSecurityGroup
	Description *string `json:"description"`
	// StatefulEgress defines whether a NetworkSecurityGroup's egress rules will be automatically stateful
	StatefulEgress *bool `json:"statefulEgress"`
	// Rules is the list of NetworkSecurityGroupRuleAttributes for the NetworkSecurityGroup
	Rules []APINetworkSecurityGroupRule `json:"rules"`
	// Labels to be associted with the NetworkSecurityGroup
	Labels map[string]string `json:"labels"`
}

// Validate ensures the values in the request are acceptable
func (req APINetworkSecurityGroupUpdateRequest) Validate(siteConfig *cdbm.SiteConfig) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.When(req.Name != nil, validation.Required.Error(validationErrorStringLength)),
			validation.When(req.Name != nil, validation.By(util.ValidateNameCharacters)),
			validation.When(req.Name != nil, validation.Length(2, 256).Error(validationErrorStringLength))),
		validation.Field(&req.Description,
			validation.When(req.Description != nil, validation.Length(0, 1024).Error(validationErrorDescriptionStringLength)),
		),
	)

	if err != nil {
		return err
	}

	maxRules := MaxNetworkSecurityGroupRules
	if siteConfig != nil && siteConfig.MaxNetworkSecurityGroupRuleCount != nil {
		maxRules = *siteConfig.MaxNetworkSecurityGroupRuleCount
	}

	if len(req.Rules) > maxRules {
		return validation.Errors{
			"rules": fmt.Errorf("number of rules cannot exceed %d", maxRules),
		}
	}

	// Individual rule validation happens later during
	// processing when we convert from request rules to
	// the protobuf representation.

	if err := util.ValidateLabels(req.Labels); err != nil {
		return err
	}

	return nil
}

// APINetworkSecurityGroup is the data structure to capture API representation of a NetworkSecurityGroup
type APINetworkSecurityGroup struct {
	// ID is the unique UUID v4 identifier for the NetworkSecurityGroup
	ID string `json:"id"`
	// Name is the name of the NetworkSecurityGroup
	Name string `json:"name"`
	// Description is the description of the NetworkSecurityGroup
	Description *string `json:"description"`
	// SiteID is the ID of the Site
	SiteID string `json:"siteId"`
	// Site is the summary of the Site
	Site *APISiteSummary `json:"site,omitempty"`
	// TenantID is the ID of the Tenant
	TenantID string `json:"tenantId"`
	// Tenant is the summary of the tenant
	Tenant *APITenantSummary `json:"tenant,omitempty"`
	// Status is the status of the NetworkSecurityGroup
	Status string `json:"status"`
	// StatusHistory is the status detail records for the site over time
	StatusHistory []APIStatusDetail `json:"statusHistory"`
	// StatefulEgress defines whether a NetworkSecurityGroup's egress rules will be automatically stateful
	StatefulEgress bool `json:"statefulEgress"`
	// Rules is the list of NetworkSecurityGroupRuleAttributes for the NetworkSecurityGroup
	Rules []*APINetworkSecurityGroupRule `json:"rules"`
	// Labels is the set of labels/tags for the NetworkSecurityGroup
	Labels map[string]string `json:"labels"`
	// Created indicates the ISO datetime string for when the NetworkSecurityGroup was created
	Created time.Time `json:"created"`
	// Updated indicates the ISO datetime string for when the NetworkSecurityGroup was last updated
	Updated time.Time `json:"updated"`
	// AttachmentStats holds the counts for objects that have
	// Attached the NSG if requested.
	AttachmentStats *APINetworkSecurityGroupStats `json:"attachmentStats"`
	// RuleCount hold the count of the number of rules in the NetworkSecurityGroup
	RuleCount int `json:"ruleCount"`
}

// Accepts a rule definition from an API request and converts
// it to the proto representation that will be stored and passed
// to NICo
func ProtobufRuleFromAPINetworkSecurityGroupRule(rule *APINetworkSecurityGroupRule) (*cdbm.NetworkSecurityGroupRule, error) {

	if rule.Priority < NetworkSecurityGroupRulePriorityMin || rule.Priority > NetworkSecurityGroupRulePriorityMax {
		return nil, validation.Errors{"rules": fmt.Errorf("priority `%d` must be between 0 and 60000", rule.Priority)}
	}

	// Process rule direction
	rule.Direction = strings.ToUpper(rule.Direction)
	direction, found := NetworkSecurityGroupRuleProtobufDirectionFromAPIDirection[rule.Direction]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown direction `%s`", rule.Direction)}
	}

	// Process rule action
	rule.Action = strings.ToUpper(rule.Action)
	action, found := NetworkSecurityGroupRuleProtobufActionFromAPIAction[rule.Action]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown action `%s`", rule.Action)}
	}

	// Process rule protocol
	rule.Protocol = strings.ToUpper(rule.Protocol)
	protocol, found := NetworkSecurityGroupRuleProtobufProtocolFromAPIProtocol[rule.Protocol]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown protocol `%s`", rule.Protocol)}
	}

	// Some protocols don't allow ports, so let's check for that.
	switch rule.Protocol {
	case APINetworkSecurityGroupRuleProtocolAny, APINetworkSecurityGroupRuleProtocolIcmp, APINetworkSecurityGroupRuleProtocolIcmp6:
		if rule.SourcePortRange != nil || rule.DestinationPortRange != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("ports cannot be specified with protocol `%s`", rule.Protocol)}
		}
	}

	// Process src/dst port ranges

	srcPortStart, srcPortEnd, err := hutil.StringPtrToPortRangeUint32PtrPair(rule.SourcePortRange)
	if err != nil {
		return nil, validation.Errors{"rules": fmt.Errorf("unable to parse source port range in API request: %w", err)}
	}

	dstPortStart, dstPortEnd, err := hutil.StringPtrToPortRangeUint32PtrPair(rule.DestinationPortRange)
	if err != nil {
		return nil, validation.Errors{"rules": fmt.Errorf("unable to parse destination port range in API request: %w", err)}
	}

	newRule := &cdbm.NetworkSecurityGroupRule{
		NetworkSecurityGroupRuleAttributes: &cwssaws.NetworkSecurityGroupRuleAttributes{
			Id:        rule.Name,
			Direction: direction,
			Protocol:  protocol,
			Action:    action,
			Priority:  uint32(rule.Priority),
			Ipv6:      false, // We have support for it in ACLs but pretty much nowhere else, so hide this for now.

			SrcPortStart: srcPortStart,
			SrcPortEnd:   srcPortEnd,
			DstPortStart: dstPortStart,
			DstPortEnd:   dstPortEnd,
		},
	}

	// Process src/dst prefixes

	// We currently only have a single source network
	// option supported.
	// As/If we add more, add more if-blocks
	// and checking the final count will be a
	// pretty cheap way to make sure we have only
	// one.

	// Process source net

	sourceNetOptionCount := 0

	if rule.SourcePrefix != nil {

		if _, _, err := net.ParseCIDR(*rule.SourcePrefix); err != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("source prefix `%s` is not valid", *rule.SourcePrefix)}
		}

		newRule.SourceNet = &cwssaws.NetworkSecurityGroupRuleAttributes_SrcPrefix{SrcPrefix: *rule.SourcePrefix}
		sourceNetOptionCount++
	}

	if sourceNetOptionCount > 1 {
		return nil, validation.Errors{"rules": fmt.Errorf("too many source network options found in API request")}
	}

	if sourceNetOptionCount == 0 {
		return nil, validation.Errors{"rules": fmt.Errorf("required source network option not found in API request")}
	}

	// Process destination net

	destinationNetOptionCount := 0

	if rule.DestinationPrefix != nil {

		if _, _, err := net.ParseCIDR(*rule.DestinationPrefix); err != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("destination prefix `%s` is not valid", *rule.DestinationPrefix)}
		}

		newRule.DestinationNet = &cwssaws.NetworkSecurityGroupRuleAttributes_DstPrefix{DstPrefix: *rule.DestinationPrefix}
		destinationNetOptionCount++
	}

	if destinationNetOptionCount > 1 {
		return nil, validation.Errors{"rules": fmt.Errorf("too many destination network options found in API request")}
	}

	if destinationNetOptionCount == 0 {
		return nil, validation.Errors{"rules": fmt.Errorf("required destination network option not found in API request")}
	}

	return newRule, nil
}

// Accepts a NICo rule definition and converts
// it to the nico-rest-api request representation that will be
// returned to users
func APINetworkSecurityGroupRuleFromProtobufRule(rule *cdbm.NetworkSecurityGroupRule) (*APINetworkSecurityGroupRule, error) {

	if rule.Priority > NetworkSecurityGroupRulePriorityMax {
		return nil, validation.Errors{"rules": fmt.Errorf("priority `%d` must be between 0 and 60000", rule.Priority)}
	}

	// Process rule direction
	direction, found := NetworkSecurityGroupRuleAPIDirectionFromProtobufDirection[rule.Direction]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown direction in database record, %s (%d)", rule.Direction.String(), rule.Direction.Number())}
	}

	// Process rule action
	action, found := NetworkSecurityGroupRuleAPIActionFromProtobufAction[rule.Action]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown action in database record, %s (%d)", rule.Action.String(), rule.Action.Number())}
	}

	// Process rule protocol
	protocol, found := NetworkSecurityGroupRuleAPIProtocolFromProtobufProtocol[rule.Protocol]
	if !found {
		return nil, validation.Errors{"rules": fmt.Errorf("unknown protocol in database record, %s (%d)", rule.Protocol.String(), rule.Protocol.Number())}
	}

	// Some protocols don't allow ports, so let's check for that.
	switch protocol {
	case APINetworkSecurityGroupRuleProtocolAny, APINetworkSecurityGroupRuleProtocolIcmp, APINetworkSecurityGroupRuleProtocolIcmp6:
		if rule.SrcPortStart != nil || rule.DstPortStart != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("found ports incorrectly specified with protocol `%s` in database record", protocol)}
		}
	}

	// Process rule source and destination networks

	var srcPrefix *string
	var dstPrefix *string

	switch srcNet := rule.GetSourceNet().(type) {
	case *cwssaws.NetworkSecurityGroupRuleAttributes_SrcPrefix:
		if _, _, err := net.ParseCIDR(srcNet.SrcPrefix); err != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("found invalid source prefix `%s` in database record", srcNet.SrcPrefix)}
		}
		srcPrefix = &srcNet.SrcPrefix
	default:
		return nil, validation.Errors{"rules": fmt.Errorf("encountered unknown source network option in database record")}
	}

	switch dstNet := rule.GetDestinationNet().(type) {
	case *cwssaws.NetworkSecurityGroupRuleAttributes_DstPrefix:
		if _, _, err := net.ParseCIDR(dstNet.DstPrefix); err != nil {
			return nil, validation.Errors{"rules": fmt.Errorf("found invalid destination prefix `%s` in database record", dstNet.DstPrefix)}
		}
		dstPrefix = &dstNet.DstPrefix
	default:
		return nil, fmt.Errorf("encountered unknown source network option in database record")
	}

	// Process rule port ranges
	var srcPortRange *string
	var dstPortRange *string

	// Whether nico-rest-api validates ranges or not,
	// NICo will reject half-defined port ranges.
	// If we see a half-defined range, it means DB
	// corruption.
	if rule.SrcPortStart != nil || rule.SrcPortEnd != nil {
		if rule.SrcPortStart == nil || rule.SrcPortEnd == nil {
			return nil, errors.New("encountered half-defined source port range in database record")
		}
		srcPortRangeStr := fmt.Sprintf("%d-%d", *rule.SrcPortStart, *rule.SrcPortEnd)
		srcPortRange = &srcPortRangeStr
	}

	if rule.DstPortStart != nil || rule.DstPortEnd != nil {
		if rule.DstPortStart == nil || rule.DstPortEnd == nil {
			return nil, errors.New("encountered half-defined destination port range in database record")
		}
		dstPortRangeStr := fmt.Sprintf("%d-%d", *rule.DstPortStart, *rule.DstPortEnd)
		dstPortRange = &dstPortRangeStr
	}

	return &APINetworkSecurityGroupRule{
		Name:                 rule.Id,
		Direction:            direction,
		SourcePortRange:      srcPortRange,
		DestinationPortRange: dstPortRange,
		Protocol:             protocol,
		Action:               action,
		Priority:             int(rule.Priority),
		SourcePrefix:         srcPrefix,
		DestinationPrefix:    dstPrefix,
	}, nil
}

// NewAPINetworkSecurityGroup accepts a DB layer NetworkSecurityGroup object and returns an API object
func NewAPINetworkSecurityGroup(dsg *cdbm.NetworkSecurityGroup, dbsds []cdbm.StatusDetail) (*APINetworkSecurityGroup, error) {
	apisg := &APINetworkSecurityGroup{
		ID:             dsg.ID,
		Name:           dsg.Name,
		Description:    dsg.Description,
		SiteID:         dsg.SiteID.String(),
		TenantID:       dsg.TenantID.String(),
		Labels:         dsg.Labels,
		Status:         dsg.Status,
		Created:        dsg.Created,
		Updated:        dsg.Updated,
		StatefulEgress: dsg.StatefulEgress,
	}

	if dsg.Site != nil {
		apisg.Site = NewAPISiteSummary(dsg.Site)
	}

	if dsg.Tenant != nil {
		apisg.Tenant = NewAPITenantSummary(dsg.Tenant)
	}

	apisg.StatusHistory = []APIStatusDetail{}
	for _, dbsd := range dbsds {
		apisg.StatusHistory = append(apisg.StatusHistory, NewAPIStatusDetail(dbsd))
	}

	rules := make([]*APINetworkSecurityGroupRule, len(dsg.Rules))

	for i, rule := range dsg.Rules {
		newRule, err := APINetworkSecurityGroupRuleFromProtobufRule(rule)
		if err != nil {
			return nil, err
		}

		rules[i] = newRule
	}

	apisg.Rules = rules
	apisg.RuleCount = len(rules)

	return apisg, nil
}

type APINetworkSecurityGroupRule struct {
	Name                 *string `json:"name"`
	Direction            string  `json:"direction"`
	SourcePortRange      *string `json:"sourcePortRange"`
	DestinationPortRange *string `json:"destinationPortRange"`
	Protocol             string  `json:"protocol"`
	Action               string  `json:"action"`
	Priority             int     `json:"priority"`
	SourcePrefix         *string `json:"sourcePrefix"`
	DestinationPrefix    *string `json:"destinationPrefix"`
}

// APINetworkSecurityGroupStats holds detailed usage stats for an NSG
type APINetworkSecurityGroupStats struct {
	// InUse is a convenience field that will be true
	// if TotalAttachmentCount > 0
	InUse bool `json:"inUse"`
	// VpcAttachmentCount holds the count of the number of VPCs that have the NSG directly attached.
	VpcAttachmentCount int `json:"directVpcAttachmentCount"`
	// InstanceAttachmentCount holds the count of the number of instances that have the NSG directly attached.
	InstanceAttachmentCount int `json:"directInstanceAttachmentCount"`
	// TotalAttachmentCount holds the total count of all objects that have
	// the NSG directly attached.
	TotalAttachmentCount int `json:"totalDirectAttachmentCount"`
}

// APINetworkSecurityGroupSummary is the data structure to capture API summary of a NetworkSecurityGroup
type APINetworkSecurityGroupSummary struct {
	// ID of the NetworkSecurityGroup
	ID string `json:"id"`
	// Name of the NetworkSecurityGroup
	Name string `json:"name"`
	// Description of the NetworkSecurityGroup
	Description *string `json:"description"`
	// Status is the status of the NetworkSecurityGroup
	Status string `json:"status"`
	// StatefulEgress defines whether a NetworkSecurityGroup's egress rules will be automatically stateful
	StatefulEgress bool `json:"statefulEgress"`
	// RuleCount hold the count of the number of rules in the NetworkSecurityGroup
	RuleCount int `json:"ruleCount"`
}

// NewAPINetworkSecurityGroupSummary accepts a DB layer NetworkSecurityGroup object returns an API layer object
func NewAPINetworkSecurityGroupSummary(dbsg *cdbm.NetworkSecurityGroup) *APINetworkSecurityGroupSummary {
	asg := APINetworkSecurityGroupSummary{
		ID:             dbsg.ID,
		Name:           dbsg.Name,
		Description:    dbsg.Description,
		Status:         dbsg.Status,
		RuleCount:      len(dbsg.Rules),
		StatefulEgress: dbsg.StatefulEgress,
	}

	return &asg
}

type APINetworkSecurityGroupPropagationDetails struct {
	// The ID of the object (VPC/Instance/etc) for these details
	ObjectID string `json:"object_id"`
	// The detailed propagation status that was
	// actually returned from NICo
	DetailedStatus string `json:"detailedStatus"`
	// The simplified propagation status
	// that reduces the actual status to just
	// a few values.
	Status string `json:"status"`
	// Additional details for the status
	Details *string `json:"details"`
	// IDs of the instances involved in determining the
	// propagation status
	RelatedInstanceIds []string `json:"relatedInstanceIds"`
	// IDs of any instances associated with the ObjectID that have
	// not yet updated their NSG rules.
	UnpropagatedInstanceIds []string `json:"unpropagatedInstanceIds"`
}

func NewAPINetworkSecurityGroupPropagationDetails(s *cdbm.NetworkSecurityGroupPropagationDetails) *APINetworkSecurityGroupPropagationDetails {
	if s == nil {
		return nil
	}

	details := &APINetworkSecurityGroupPropagationDetails{
		ObjectID:                s.NetworkSecurityGroupPropagationObjectStatus.Id,
		Details:                 s.NetworkSecurityGroupPropagationObjectStatus.Details,
		RelatedInstanceIds:      s.NetworkSecurityGroupPropagationObjectStatus.RelatedInstanceIds,
		UnpropagatedInstanceIds: s.NetworkSecurityGroupPropagationObjectStatus.UnpropagatedInstanceIds,
	}

	status, found := NetworkSecurityGroupRuleAPIPropagationDetailedStatusFromProtobufPropagationStatus[s.Status]
	if !found {
		// We could return an error, but we should probably _not_ fail
		// a VPC/Instance/etc handler response just because a new status
		// arrived in the proto and we don't know about it; so, we can respond
		// with Unknown, since we don't know, and provide the details message
		// so that users, and we, know this is related to a mismatch between
		// site data and our expectations.
		status = APINetworkSecurityGroupPropagationDetailedStatusUnknown
		details.Details = cdb.GetStrPtr("Unknown status type reported from Site")
	}

	details.DetailedStatus = status

	status, found = NetworkSecurityGroupRuleAPIPropagationStatusFromProtobufPropagationStatus[s.Status]
	if !found {
		status = APINetworkSecurityGroupPropagationStatusError
	}

	details.Status = status

	return details
}
