// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleFilterMatches(t *testing.T) {
	eventType := Type("test.event")
	otherEventType := Type("other.event")
	origin := RuleOriginPersisted
	otherOrigin := RuleOriginBuiltIn
	enabled := true
	disabled := false
	rule := &Rule{
		EventType: eventType,
		Origin:    origin,
		Enabled:   enabled,
	}

	tests := map[string]struct {
		filter RuleFilter
		rule   *Rule
		want   bool
	}{
		"empty filter": {
			rule: rule,
			want: true,
		},
		"all fields match": {
			filter: RuleFilter{EventType: &eventType, Origin: &origin, Enabled: &enabled},
			rule:   rule,
			want:   true,
		},
		"event type differs": {
			filter: RuleFilter{EventType: &otherEventType},
			rule:   rule,
			want:   false,
		},
		"origin differs": {
			filter: RuleFilter{Origin: &otherOrigin},
			rule:   rule,
			want:   false,
		},
		"enabled differs": {
			filter: RuleFilter{Enabled: &disabled},
			rule:   rule,
			want:   false,
		},
		"nil rule": {
			rule: nil,
			want: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, test.filter.Matches(test.rule))
		})
	}
}
