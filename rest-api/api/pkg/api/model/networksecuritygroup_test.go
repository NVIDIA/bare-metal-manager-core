// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// A helper only for tests.  Ignores potential conversion errors.
func getIntPtrToUint32Ptr(i *int) *uint32 {
	if i == nil {
		return nil
	}

	i32 := uint32(*i)

	return &i32
}

func TestAPINetworkSecurityGroupRuleConversions(t *testing.T) {

	directionEnumLimit := len(cwssaws.NetworkSecurityGroupRuleDirection_value)
	protocolEnumLimit := len(cwssaws.NetworkSecurityGroupRuleProtocol_value)
	actionEnumLimit := len(cwssaws.NetworkSecurityGroupRuleAction_value)

	srcPortStarts := []*uint32{
		nil,
		getIntPtrToUint32Ptr(cdb.GetIntPtr(50)),
	}

	srcPortEnds := []*uint32{
		nil,
		getIntPtrToUint32Ptr(cdb.GetIntPtr(50)),
	}

	dstPortStarts := []*uint32{
		nil,
		getIntPtrToUint32Ptr(cdb.GetIntPtr(80)),
	}

	dstPortEnds := []*uint32{
		nil,
		getIntPtrToUint32Ptr(cdb.GetIntPtr(80)),
	}

	allRules := []*cdbm.NetworkSecurityGroupRule{}
	validRules := []*cdbm.NetworkSecurityGroupRule{}

	// Generate all the rules combinations

	for dI := range directionEnumLimit {
		for pI := range protocolEnumLimit {
			for aI := range actionEnumLimit {
				for _, sps := range srcPortStarts {
					for _, spe := range srcPortEnds {
						for _, dps := range dstPortStarts {
							for _, dpe := range dstPortEnds {

								d := cwssaws.NetworkSecurityGroupRuleDirection(uint32(dI))
								p := cwssaws.NetworkSecurityGroupRuleProtocol(uint32(pI))
								a := cwssaws.NetworkSecurityGroupRuleAction(uint32(aI))

								newRule := &cdbm.NetworkSecurityGroupRule{
									NetworkSecurityGroupRuleAttributes: &cwssaws.NetworkSecurityGroupRuleAttributes{
										Id:             cdb.GetStrPtr(uuid.NewString()),
										Direction:      d,
										Protocol:       p,
										Action:         a,
										Priority:       55,
										Ipv6:           false, // We have support for it in ACLs but pretty much nowhere else, so we hide this for now.
										SrcPortStart:   sps,
										SrcPortEnd:     spe,
										DstPortStart:   dps,
										DstPortEnd:     dpe,
										SourceNet:      &cwssaws.NetworkSecurityGroupRuleAttributes_SrcPrefix{SrcPrefix: "0.0.0.0/0"},
										DestinationNet: &cwssaws.NetworkSecurityGroupRuleAttributes_DstPrefix{DstPrefix: "1.1.1.1/0"},
									},
								}

								allRules = append(allRules, newRule)

								if d != cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INVALID &&
									p != cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_INVALID &&
									a != cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_INVALID &&
									// src/dst start and end pairs are mutually required.
									// Either start and end or both nil or neither is allowed to be nil.
									((sps == nil) == (spe == nil)) &&
									((dps == nil) == (dpe == nil)) &&
									// Exclude rules that have invalid port + protocol combinations.
									!((sps != nil || dps != nil) &&
										(p == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ANY ||
											p == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP ||
											p == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP6)) {

									validRules = append(validRules, newRule)
									continue
								}
							}
						}
					}
				}

			}
		}
	}

	// The set of valid rules should not be as big
	// as the set of all the generated rules.
	assert.True(t, len(allRules) > len(validRules))

	// Convert to API rules
	// We'll loop through all rules, but we expect errors for the
	// invalid ones and a final count that contains only the valid ones.
	i := 0
	for _, rule := range allRules {

		apiRule, err := APINetworkSecurityGroupRuleFromProtobufRule(rule)

		failMsg := fmt.Sprintf("\nNICo Rule\n\n%+v\n\nAPI Rule\n\n%+v\n\n", rule, apiRule)

		// Here, we're doing the inverse of what we did during rule generation where we
		// excluded matching rules from the set of validRules.
		// Now, we want to match on the _invalid_ rules and make sure they generate an error.
		if rule.Direction == cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INVALID ||
			rule.Protocol == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_INVALID ||
			rule.Action == cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_INVALID ||
			((rule.SrcPortStart == nil) != (rule.SrcPortEnd == nil)) ||
			((rule.DstPortStart == nil) != (rule.DstPortEnd == nil)) ||
			(rule.SrcPortStart != nil || rule.DstPortStart != nil) &&
				(rule.Protocol == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ANY ||
					rule.Protocol == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP ||
					rule.Protocol == cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_ICMP6) {

			assert.NotNil(t, err, failMsg)
			continue
		}

		assert.Nil(t, err, failMsg)

		// Convert back again
		newRule, err := ProtobufRuleFromAPINetworkSecurityGroupRule(apiRule)

		if !assert.Nil(t, err, failMsg) {
			if e, ok := err.(validation.Errors); ok {
				msg, _ := e.MarshalJSON()
				t.Fatalf("API validation failure: %s", msg)
			}
		}

		// Compare the double-conversion to the original of rule
		assert.True(t, proto.Equal(validRules[i], newRule), fmt.Sprintf("\nNICo Rule\n\n%+v\n\nAPI Rule\n\n%+v\n\nNew NICo Rule\n\n%+v\n", rule, apiRule, newRule))

		// Track the valid rule index
		i++
	}

	// Test some invalid API request cases
	// The first entry is a known good one.
	// The rest are invalid
	directions := []string{APINetworkSecurityGroupRuleDirectionIngress, "outer space", ""}
	protocol := []string{APINetworkSecurityGroupRuleProtocolTcp, "MPLS", ""}
	actions := []string{APINetworkSecurityGroupRuleActionPermit, "explode", ""}
	priorities := []int{0, -1, 99999}

	srcPortRanges := []string{"80-81", "abc", "a-b", "-70", "70-"}
	dstPortRanges := []string{"90-91", "xyz", "d-e", "-90", "90-"}
	srcPrefixes := []*string{cdb.GetStrPtr("0.0.0.0/0"), nil}
	dstPrefixes := []*string{cdb.GetStrPtr("1.1.1.1/0"), nil}

	for dI, d := range directions {
		for pI, p := range protocol {
			for aI, a := range actions {
				for srI, sr := range srcPortRanges {
					for drI, dr := range dstPortRanges {
						for spI, sp := range srcPrefixes {
							for dpI, dp := range dstPrefixes {
								for prioI, prio := range priorities {

									rule := &APINetworkSecurityGroupRule{
										Direction:            d,
										Protocol:             p,
										Action:               a,
										SourcePortRange:      cdb.GetStrPtr(sr),
										DestinationPortRange: cdb.GetStrPtr(dr),
										SourcePrefix:         sp,
										DestinationPrefix:    dp,
										Priority:             prio,
									}

									failMsg := fmt.Sprintf("\n%v\n%v\n%v\n%v\n%v\n%v\n%v\n%d\n\n%+v\n", d, p, a, sr, dr, sp, dp, prio, rule)

									// Now, convert to a NICo/proto rule
									nicoRule, err := ProtobufRuleFromAPINetworkSecurityGroupRule(rule)

									// If this rule has all the known good entries,
									// it should have passed (converted successfully).
									if dI == 0 && pI == 0 && aI == 0 && srI == 0 && drI == 0 && spI == 0 && dpI == 0 && prioI == 0 {
										assert.Nil(t, err, failMsg)

										// Now, convert back again so we can confirm that all conversions
										// are symmetric.
										apiRule, err := APINetworkSecurityGroupRuleFromProtobufRule(nicoRule)

										assert.Nil(t, err, failMsg)

										// Compare the original rule to the one that
										// came out of the double-conversion.
										assert.Equal(t, rule, apiRule, failMsg)

									} else {
										// For every other case it should fail.
										// The combos ensure that each bad property gets
										// tested with every other property set to a known
										// good value.
										assert.NotNil(t, err, failMsg)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestAPINetworkSecurityGroupCreateRequest_Validate(t *testing.T) {

	rules := []APINetworkSecurityGroupRule{
		{Direction: APINetworkSecurityGroupRuleProtocolTcp, SourcePortRange: cdb.GetStrPtr("80-81"), Protocol: APINetworkSecurityGroupRuleProtocolTcp, Action: APINetworkSecurityGroupRuleActionPermit},
	}

	tests := []struct {
		desc       string
		obj        APINetworkSecurityGroupCreateRequest
		siteConfig *cdbm.SiteConfig
		expectErr  bool
	}{
		{
			desc:      "ok when only required fields are provided",
			obj:       APINetworkSecurityGroupCreateRequest{Name: "test", SiteID: uuid.New().String()},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APINetworkSecurityGroupCreateRequest{Name: "test", Description: cdb.GetStrPtr("test"), SiteID: uuid.New().String(), StatefulEgress: true, Rules: rules},
			expectErr: false,
		},
		{
			desc:      "error when required fields are not provided",
			obj:       APINetworkSecurityGroupCreateRequest{Name: "test", Rules: rules},
			expectErr: true,
		},
		{
			desc:       "error when too many rules are sent",
			obj:        APINetworkSecurityGroupCreateRequest{Name: "test", Rules: rules},
			siteConfig: &cdbm.SiteConfig{MaxNetworkSecurityGroupRuleCount: cdb.GetIntPtr(0)},
			expectErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate(tc.siteConfig)
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPINetworkSecurityGroupUpdateRequest_Validate(t *testing.T) {

	rules := []APINetworkSecurityGroupRule{
		{Direction: APINetworkSecurityGroupRuleProtocolTcp, SourcePortRange: cdb.GetStrPtr("80-81"), Protocol: APINetworkSecurityGroupRuleProtocolTcp, Action: APINetworkSecurityGroupRuleActionPermit},
	}

	tests := []struct {
		desc       string
		obj        APINetworkSecurityGroupUpdateRequest
		siteConfig *cdbm.SiteConfig
		expectErr  bool
	}{
		{
			desc:      "ok when only some fields are provided",
			obj:       APINetworkSecurityGroupUpdateRequest{Name: cdb.GetStrPtr("updatedname")},
			expectErr: false,
		},
		{
			desc:      "ok when all fields are provided",
			obj:       APINetworkSecurityGroupUpdateRequest{Name: cdb.GetStrPtr("updatedname"), Description: cdb.GetStrPtr("updated"), StatefulEgress: cdb.GetBoolPtr(true), Rules: rules},
			expectErr: false,
		},
		{
			desc:       "error when too many rules are sent",
			obj:        APINetworkSecurityGroupUpdateRequest{Name: cdb.GetStrPtr("updatedname"), Description: cdb.GetStrPtr("updated"), Rules: rules},
			siteConfig: &cdbm.SiteConfig{MaxNetworkSecurityGroupRuleCount: cdb.GetIntPtr(0)},
			expectErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate(tc.siteConfig)
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPINetworkSecurityGroupNew(t *testing.T) {
	rules := []*cdbm.NetworkSecurityGroupRule{
		{
			NetworkSecurityGroupRuleAttributes: &cwssaws.NetworkSecurityGroupRuleAttributes{
				Action:         cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_PERMIT,
				Direction:      cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INGRESS,
				SrcPortStart:   getIntPtrToUint32Ptr(cdb.GetIntPtr(0)),
				SrcPortEnd:     getIntPtrToUint32Ptr(cdb.GetIntPtr(100)),
				Protocol:       cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_TCP,
				SourceNet:      &cwssaws.NetworkSecurityGroupRuleAttributes_SrcPrefix{SrcPrefix: "0.0.0.0/0"},
				DestinationNet: &cwssaws.NetworkSecurityGroupRuleAttributes_DstPrefix{DstPrefix: "0.0.0.0/0"},
			},
		},
	}

	dbSG := &cdbm.NetworkSecurityGroup{
		ID:             uuid.NewString(),
		Name:           "test",
		StatefulEgress: true,
		Rules:          rules,
		Description:    cdb.GetStrPtr("test"),
		SiteID:         uuid.New(),
		TenantID:       uuid.New(),
		Status:         cdbm.NetworkSecurityGroupStatusReady,
		Created:        cdb.GetCurTime(),
		Updated:        cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbSG.ID,
			Status:   cdbm.NetworkSecurityGroupStatusReady,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}

	tests := []struct {
		desc  string
		dbObj *cdbm.NetworkSecurityGroup
		dbSds []cdbm.StatusDetail
	}{
		{
			desc:  "test creating API NetworkSecurityGroup",
			dbObj: dbSG,
			dbSds: dbsds,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := NewAPINetworkSecurityGroup(tc.dbObj, tc.dbSds)
			assert.Nil(t, err)
			assert.Equal(t, tc.dbObj.ID, got.ID)
		})
	}
}

func TestAPINetworkSecurityGroupNewSummary(t *testing.T) {
	rules := []*cdbm.NetworkSecurityGroupRule{
		{
			NetworkSecurityGroupRuleAttributes: &cwssaws.NetworkSecurityGroupRuleAttributes{
				Action:         cwssaws.NetworkSecurityGroupRuleAction_NSG_RULE_ACTION_PERMIT,
				Direction:      cwssaws.NetworkSecurityGroupRuleDirection_NSG_RULE_DIRECTION_INGRESS,
				SrcPortStart:   getIntPtrToUint32Ptr(cdb.GetIntPtr(0)),
				SrcPortEnd:     getIntPtrToUint32Ptr(cdb.GetIntPtr(100)),
				Protocol:       cwssaws.NetworkSecurityGroupRuleProtocol_NSG_RULE_PROTO_TCP,
				SourceNet:      &cwssaws.NetworkSecurityGroupRuleAttributes_SrcPrefix{SrcPrefix: "0.0.0.0/0"},
				DestinationNet: &cwssaws.NetworkSecurityGroupRuleAttributes_DstPrefix{DstPrefix: "0.0.0.0/0"},
			},
		},
	}

	dbSG := &cdbm.NetworkSecurityGroup{
		ID:             uuid.NewString(),
		Name:           "test",
		StatefulEgress: true,
		Rules:          rules,
		Description:    cdb.GetStrPtr("test"),
		SiteID:         uuid.New(),
		TenantID:       uuid.New(),
		Status:         cdbm.NetworkSecurityGroupStatusReady,
		Created:        cdb.GetCurTime(),
		Updated:        cdb.GetCurTime(),
	}

	tests := []struct {
		desc  string
		dbObj *cdbm.NetworkSecurityGroup
		dbSds []cdbm.StatusDetail
	}{
		{
			desc:  "test creating API NetworkSecurityGroupSummary",
			dbObj: dbSG,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPINetworkSecurityGroupSummary(tc.dbObj)
			assert.Equal(t, tc.dbObj.ID, got.ID)
			assert.True(t, len(tc.dbObj.Rules) > 0, "Add some rules for the NSG for this test.")
			assert.Equal(t, len(tc.dbObj.Rules), got.RuleCount)
		})
	}
}
