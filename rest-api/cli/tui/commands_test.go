// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Upstream tests ---

func TestAppendScopeFlags_NoSession(t *testing.T) {
	got := appendScopeFlags(nil, []string{"machine", "list"})
	want := []string{"machine", "list"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_SiteScope_MachineList(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123", SiteName: "pdx-dev3"}}
	got := appendScopeFlags(s, []string{"machine", "list"})
	want := []string{"machine", "list", "--site-id", "site-123"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_SiteScope_VPCList(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123"}}
	got := appendScopeFlags(s, []string{"vpc", "list"})
	want := []string{"vpc", "list", "--site-id", "site-123"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_BothScopes_SubnetList(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123", VpcID: "vpc-456"}}
	got := appendScopeFlags(s, []string{"subnet", "list"})
	want := []string{"subnet", "list", "--site-id", "site-123", "--vpc-id", "vpc-456"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_BothScopes_InstanceList(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123", VpcID: "vpc-456"}}
	got := appendScopeFlags(s, []string{"instance", "list"})
	want := []string{"instance", "list", "--site-id", "site-123", "--vpc-id", "vpc-456"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_NonListAction_Ignored(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123"}}
	got := appendScopeFlags(s, []string{"machine", "get"})
	want := []string{"machine", "get"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_UnknownResource_NoFlags(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123"}}
	got := appendScopeFlags(s, []string{"site", "list"})
	want := []string{"site", "list"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_SinglePart_NoFlags(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-123"}}
	got := appendScopeFlags(s, []string{"help"})
	want := []string{"help"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAppendScopeFlags_VpcOnlyScope_SubnetList(t *testing.T) {
	s := &Session{Scope: Scope{VpcID: "vpc-456"}}
	got := appendScopeFlags(s, []string{"subnet", "list"})
	want := []string{"subnet", "list", "--vpc-id", "vpc-456"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLogCmd_IncludesScopeFlags(t *testing.T) {
	s := &Session{
		ConfigPath: "/tmp/config.yaml",
		Scope:      Scope{SiteID: "site-123"},
	}
	output := captureStdout(func() {
		LogCmd(s, "machine", "list")
	})
	if !strings.Contains(output, "--site-id site-123") {
		t.Errorf("LogCmd output missing --site-id flag: %q", output)
	}
	if !strings.Contains(output, "--config /tmp/config.yaml") {
		t.Errorf("LogCmd output missing --config flag: %q", output)
	}
	if !strings.Contains(output, "cli") {
		t.Errorf("LogCmd output missing cli: %q", output)
	}
}

func TestLogCmd_NoScope(t *testing.T) {
	s := &Session{}
	output := captureStdout(func() {
		LogCmd(s, "machine", "list")
	})
	if strings.Contains(output, "--site-id") {
		t.Errorf("LogCmd output should not contain --site-id when no scope set: %q", output)
	}
}

// --- VPC scope coverage tests ---

func TestAppendScopeFlags_SiteOnly(t *testing.T) {
	siteOnlyResources := []string{
		"vpc", "allocation", "ip-block", "operating-system", "ssh-key-group",
		"network-security-group", "sku", "rack", "expected-machine",
		"expected-rack", "expected-switch", "expected-power-shelf", "tray",
		"dpu-extension-service", "infiniband-partition", "nvlink-logical-partition",
	}

	s := &Session{Scope: Scope{SiteID: "site-1", VpcID: "vpc-1"}}

	for _, resource := range siteOnlyResources {
		got := appendScopeFlags(s, []string{resource, "list"})
		if !contains(got, "--site-id") {
			t.Errorf("%s list: expected --site-id flag", resource)
		}
		if contains(got, "--vpc-id") {
			t.Errorf("%s list: should not include --vpc-id flag", resource)
		}
	}
}

func TestAppendScopeFlags_SiteAndVPC(t *testing.T) {
	vpcResources := []string{"subnet", "vpc-prefix", "instance", "machine"}

	s := &Session{Scope: Scope{SiteID: "site-1", VpcID: "vpc-1"}}

	for _, resource := range vpcResources {
		got := appendScopeFlags(s, []string{resource, "list"})
		if !contains(got, "--site-id") {
			t.Errorf("%s list: expected --site-id flag", resource)
		}
		if !contains(got, "--vpc-id") {
			t.Errorf("%s list: expected --vpc-id flag", resource)
		}
	}
}

func TestAppendScopeFlags_NoScope(t *testing.T) {
	s := &Session{Scope: Scope{}}

	got := appendScopeFlags(s, []string{"machine", "list"})
	if contains(got, "--site-id") || contains(got, "--vpc-id") {
		t.Error("empty scope should not produce any flags")
	}
}

func TestAppendScopeFlags_VPCOnlyScope(t *testing.T) {
	s := &Session{Scope: Scope{VpcID: "vpc-1"}}

	got := appendScopeFlags(s, []string{"instance", "list"})
	if contains(got, "--site-id") {
		t.Error("should not include --site-id when SiteID is empty")
	}
	if !contains(got, "--vpc-id") {
		t.Error("expected --vpc-id flag")
	}
}

func TestAppendScopeFlags_NonListAction(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "site-1", VpcID: "vpc-1"}}

	got := appendScopeFlags(s, []string{"machine", "get"})
	if contains(got, "--site-id") || contains(got, "--vpc-id") {
		t.Error("get actions should not have scope flags appended")
	}
}

func TestAppendScopeFlags_UnscopedResources(t *testing.T) {
	unscopedResources := []string{"site", "audit", "ssh-key", "tenant-account"}

	s := &Session{Scope: Scope{SiteID: "site-1", VpcID: "vpc-1"}}

	for _, resource := range unscopedResources {
		got := appendScopeFlags(s, []string{resource, "list"})
		if contains(got, "--site-id") || contains(got, "--vpc-id") {
			t.Errorf("%s list: unscoped resource should not have scope flags", resource)
		}
	}
}

func TestAppendScopeFlags_CoversAllRegisteredFetchers(t *testing.T) {
	scopeFilteredFetchers := []string{
		"vpc", "subnet", "instance", "machine",
		"allocation", "ip-block", "operating-system",
		"ssh-key-group", "network-security-group",
		"sku", "rack", "expected-machine", "vpc-prefix",
		"expected-rack", "expected-switch", "expected-power-shelf", "tray",
		"dpu-extension-service", "infiniband-partition", "nvlink-logical-partition",
	}

	s := &Session{Scope: Scope{SiteID: "site-1", VpcID: "vpc-1"}}

	for _, resource := range scopeFilteredFetchers {
		got := appendScopeFlags(s, []string{resource, "list"})
		if !contains(got, "--site-id") {
			t.Errorf("%s list: scope-filtered fetcher missing from appendScopeFlags", resource)
		}
	}
}

func TestInvalidateFiltered_MatchesScopeFilteredFetchers(t *testing.T) {
	scopeFilteredFetchers := []string{
		"vpc", "subnet", "instance",
		"allocation", "machine", "ip-block", "operating-system",
		"ssh-key-group", "network-security-group",
		"vpc-prefix", "rack", "expected-machine",
		"expected-rack", "expected-switch", "expected-power-shelf", "tray", "sku",
		"dpu-extension-service", "infiniband-partition", "nvlink-logical-partition",
	}

	c := NewCache()
	for _, rt := range scopeFilteredFetchers {
		c.Set(rt, []NamedItem{{Name: rt, ID: rt}})
	}
	c.Set("site", []NamedItem{{Name: "site", ID: "site"}})
	c.Set("audit", []NamedItem{{Name: "audit", ID: "audit"}})

	c.InvalidateFiltered()

	for _, rt := range scopeFilteredFetchers {
		if got := c.Get(rt); got != nil {
			t.Errorf("InvalidateFiltered did not clear scope-filtered type %q", rt)
		}
	}
	if c.Get("site") == nil {
		t.Error("InvalidateFiltered should not clear unscoped type site")
	}
	if c.Get("audit") == nil {
		t.Error("InvalidateFiltered should not clear unscoped type audit")
	}
}

func TestAppendScopeFlags_ScopeFlagCategories_Consistent(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "s", VpcID: "v"}}

	vpcFilteredInFetchers := map[string]bool{
		"subnet": true, "instance": true, "vpc-prefix": true, "machine": true,
	}

	allScoped := []string{
		"vpc", "subnet", "instance", "machine",
		"allocation", "ip-block", "operating-system",
		"ssh-key-group", "network-security-group",
		"sku", "rack", "expected-machine", "vpc-prefix",
		"expected-rack", "expected-switch", "expected-power-shelf", "tray",
		"dpu-extension-service", "infiniband-partition", "nvlink-logical-partition",
	}

	for _, resource := range allScoped {
		got := appendScopeFlags(s, []string{resource, "list"})
		hasVpc := contains(got, "--vpc-id")
		expectVpc := vpcFilteredInFetchers[resource]
		if hasVpc != expectVpc {
			t.Errorf("%s: appendScopeFlags vpc-id=%v but fetcher expects vpc=%v", resource, hasVpc, expectVpc)
		}
	}
}

func TestAllCommands_HaveUniqueNames(t *testing.T) {
	commands := AllCommands()
	seen := map[string]bool{}
	for _, cmd := range commands {
		if seen[cmd.Name] {
			t.Errorf("duplicate command name: %s", cmd.Name)
		}
		seen[cmd.Name] = true
	}
}

func TestInvalidateFiltered_ListMatchesAppendScopeFlags(t *testing.T) {
	s := &Session{Scope: Scope{SiteID: "s"}}

	c := NewCache()
	allTypes := []string{
		"vpc", "subnet", "instance",
		"allocation", "machine", "ip-block", "operating-system",
		"ssh-key-group", "network-security-group",
		"vpc-prefix", "rack", "expected-machine",
		"expected-rack", "expected-switch", "expected-power-shelf", "tray", "sku",
		"dpu-extension-service", "infiniband-partition", "nvlink-logical-partition",
		"site", "audit", "ssh-key", "tenant-account",
	}
	for _, rt := range allTypes {
		c.Set(rt, []NamedItem{{Name: rt}})
	}
	c.InvalidateFiltered()

	var invalidated, preserved []string
	for _, rt := range allTypes {
		if c.Get(rt) == nil {
			invalidated = append(invalidated, rt)
		} else {
			preserved = append(preserved, rt)
		}
	}

	for _, rt := range invalidated {
		got := appendScopeFlags(s, []string{rt, "list"})
		if !contains(got, "--site-id") {
			t.Errorf("type %q is invalidated by InvalidateFiltered but not handled by appendScopeFlags", rt)
		}
	}

	for _, rt := range preserved {
		got := appendScopeFlags(s, []string{rt, "list"})
		if contains(got, "--site-id") || contains(got, "--vpc-id") {
			t.Errorf("type %q is preserved by InvalidateFiltered but has scope flags in appendScopeFlags", rt)
		}
	}
}

func TestReadyMachineItemsForSite_FiltersByStatusAndSite(t *testing.T) {
	machines := []NamedItem{
		{Name: "m1", ID: "1", Status: "Ready", Extra: map[string]string{"siteId": "site-a"}},
		{Name: "m2", ID: "2", Status: "ready", Extra: map[string]string{"siteId": "site-a"}},
		{Name: "m3", ID: "3", Status: "NotReady", Extra: map[string]string{"siteId": "site-a"}},
		{Name: "m4", ID: "4", Status: "Ready", Extra: map[string]string{"siteId": "site-b"}},
	}

	got := readyMachineItemsForSite(machines, "site-a")
	require.Len(t, got, 2)
	assert.Equal(t, "1", got[0].ID)
	assert.Equal(t, "2", got[1].ID)
	// Labels must surface BOTH the display name (which often falls back to
	// serial number when no friendly machine label is set) AND the full
	// machine ID, so users have something stable to copy/paste even when
	// every machine in the list shares an opaque serial-number prefix.
	assert.Contains(t, got[0].Label, "m1", "label must include display name")
	assert.Contains(t, got[0].Label, "1", "label must include machine ID")
}

func TestMachineSelectLabel(t *testing.T) {
	cases := []struct {
		name       string
		item       NamedItem
		wantSubstr []string
		wantExact  string
	}{
		{
			name:       "name and id present",
			item:       NamedItem{Name: "host-01", ID: "id-abc-123"},
			wantSubstr: []string{"host-01", "id-abc-123"},
		},
		{
			name:      "only id present (no display name resolved)",
			item:      NamedItem{Name: "", ID: "id-abc-123"},
			wantExact: "id-abc-123",
		},
		{
			name:      "only name present (defensive: should not happen in practice)",
			item:      NamedItem{Name: "host-01", ID: ""},
			wantExact: "host-01",
		},
		{
			name:       "whitespace name and id",
			item:       NamedItem{Name: "  host-01  ", ID: "  id-abc  "},
			wantSubstr: []string{"host-01", "id-abc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := machineSelectLabel(tc.item)
			if tc.wantExact != "" {
				assert.Equal(t, tc.wantExact, got)
				return
			}
			for _, s := range tc.wantSubstr {
				assert.Contains(t, got, s, "label must contain %q", s)
			}
		})
	}
}

func TestInstanceUpdateInputs_ToBody(t *testing.T) {
	cases := []struct {
		name   string
		inputs instanceUpdateInputs
		want   map[string]interface{}
	}{
		{
			name:   "empty inputs produce empty body",
			inputs: instanceUpdateInputs{},
			want:   map[string]interface{}{},
		},
		{
			name:   "name and description trimmed",
			inputs: instanceUpdateInputs{name: "  new-name  ", description: " new description "},
			want: map[string]interface{}{
				"name":        "new-name",
				"description": "new description",
			},
		},
		{
			name:   "blank name and description omitted",
			inputs: instanceUpdateInputs{name: "   ", description: ""},
			want:   map[string]interface{}{},
		},
		{
			name:   "ssh key group ids included only when non-empty",
			inputs: instanceUpdateInputs{sshKeyGroupIDs: []string{"g1", "g2"}},
			want:   map[string]interface{}{"sshKeyGroupIds": []string{"g1", "g2"}},
		},
		{
			name:   "trigger reboot alone",
			inputs: instanceUpdateInputs{triggerReboot: true},
			want:   map[string]interface{}{"triggerReboot": true},
		},
		{
			name: "trigger reboot with custom ipxe and apply updates",
			inputs: instanceUpdateInputs{
				triggerReboot:        true,
				rebootWithCustomIpxe: true,
				applyUpdatesOnReboot: true,
			},
			want: map[string]interface{}{
				"triggerReboot":        true,
				"rebootWithCustomIpxe": true,
				"applyUpdatesOnReboot": true,
			},
		},
		{
			name: "reboot modifiers ignored when triggerReboot is false (server would reject them anyway)",
			inputs: instanceUpdateInputs{
				rebootWithCustomIpxe: true,
				applyUpdatesOnReboot: true,
			},
			want: map[string]interface{}{},
		},
		{
			name: "everything together marshals to a clean JSON body",
			inputs: instanceUpdateInputs{
				name:                 "new-name",
				description:          "new desc",
				osID:                 "os-1",
				sshKeyGroupIDs:       []string{"g1"},
				triggerReboot:        true,
				rebootWithCustomIpxe: true,
				applyUpdatesOnReboot: true,
			},
			want: map[string]interface{}{
				"name":                 "new-name",
				"description":          "new desc",
				"operatingSystemId":    "os-1",
				"sshKeyGroupIds":       []string{"g1"},
				"triggerReboot":        true,
				"rebootWithCustomIpxe": true,
				"applyUpdatesOnReboot": true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inputs.toBody()
			// Compare via JSON round-trip so []string and []interface{} are
			// treated as equal when their contents match -- keeps the table
			// readable without forcing every test row to use interface{} slices.
			gotJSON, err := json.Marshal(got)
			require.NoError(t, err)
			wantJSON, err := json.Marshal(tc.want)
			require.NoError(t, err)
			assert.JSONEq(t, string(wantJSON), string(gotJSON))
		})
	}
}

func TestInstanceReboot_Body_AlwaysSetsTriggerReboot(t *testing.T) {
	// Documents the cmdInstanceReboot contract: the body MUST include
	// triggerReboot=true even when the user declines both modifiers, so a
	// future refactor that switches to a different body builder cannot
	// silently produce a no-op PATCH.
	body := instanceUpdateInputs{triggerReboot: true}.toBody()
	assert.Equal(t, true, body["triggerReboot"])
	assert.NotContains(t, body, "rebootWithCustomIpxe")
	assert.NotContains(t, body, "applyUpdatesOnReboot")
}

func TestAllCommands_HasInstanceUpdateAndReboot(t *testing.T) {
	// Regression guard: the TUI command registry must expose
	// `instance update` (so users can rename, swap OS, rotate ssh key
	// groups, or trigger a reboot) and `instance reboot` (the dedicated
	// reboot abstraction).
	names := make(map[string]bool)
	for _, c := range AllCommands() {
		names[c.Name] = true
	}
	assert.True(t, names["instance update"], "TUI must expose `instance update`")
	assert.True(t, names["instance reboot"], "TUI must expose `instance reboot`")
}

func TestSetSiteScopeFromID_UpdatesScopeAndInvalidatesFiltered(t *testing.T) {
	c := NewCache()
	c.Set("site", []NamedItem{{Name: "Site Two", ID: "site-2"}})
	c.Set("machine", []NamedItem{{Name: "m1", ID: "1"}})
	s := &Session{
		Scope:    Scope{SiteID: "site-1", SiteName: "Site One", VpcID: "vpc-1", VpcName: "VPC One"},
		Cache:    c,
		Resolver: NewResolver(c),
	}

	setSiteScopeFromID(s, "site-2")

	assert.Equal(t, "site-2", s.Scope.SiteID)
	assert.Equal(t, "Site Two", s.Scope.SiteName)
	assert.Empty(t, s.Scope.VpcID, "VPC scope must be cleared when site changes")
	assert.Empty(t, s.Scope.VpcName, "VPC name must be cleared when site changes")
	assert.Nil(t, c.Get("machine"), "filtered cache must be invalidated")
}

func TestSetSiteScopeFromID_NoChangeKeepsFilteredCache(t *testing.T) {
	c := NewCache()
	c.Set("machine", []NamedItem{{Name: "m1", ID: "1"}})
	s := &Session{
		Scope:    Scope{SiteID: "site-1", SiteName: "Site One", VpcID: "vpc-1"},
		Cache:    c,
		Resolver: NewResolver(c),
	}

	setSiteScopeFromID(s, "site-1")

	assert.NotNil(t, c.Get("machine"), "machine cache should remain when scope site does not change")
	assert.Equal(t, "vpc-1", s.Scope.VpcID, "VPC scope should remain when site does not change")
}

// --- Label support tests ---

func TestExtractLabels(t *testing.T) {
	t.Run("valid map", func(t *testing.T) {
		m := map[string]interface{}{
			"labels": map[string]interface{}{"env": "prod", "rack": "A3"},
		}
		got := extractLabels(m)
		require.Len(t, got, 2)
		assert.Equal(t, "prod", got["env"])
		assert.Equal(t, "A3", got["rack"])
	})
	t.Run("nil labels", func(t *testing.T) {
		m := map[string]interface{}{"name": "test"}
		assert.Nil(t, extractLabels(m))
	})
	t.Run("non-string values ignored", func(t *testing.T) {
		m := map[string]interface{}{
			"labels": map[string]interface{}{"env": "prod", "count": 42},
		}
		got := extractLabels(m)
		require.Len(t, got, 1)
		assert.Equal(t, "prod", got["env"])
	})
	t.Run("empty map", func(t *testing.T) {
		m := map[string]interface{}{
			"labels": map[string]interface{}{},
		}
		assert.Nil(t, extractLabels(m))
	})
}

func TestFormatLabels(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", formatLabels(nil, 60))
	})
	t.Run("single", func(t *testing.T) {
		assert.Equal(t, "env=prod", formatLabels(map[string]string{"env": "prod"}, 60))
	})
	t.Run("multiple sorted", func(t *testing.T) {
		assert.Equal(t, "env=prod, rack=A3", formatLabels(map[string]string{"rack": "A3", "env": "prod"}, 60))
	})
	t.Run("truncation", func(t *testing.T) {
		got := formatLabels(map[string]string{"env": "production", "rack": "A3"}, 15)
		assert.LessOrEqual(t, len(got), 15)
		assert.True(t, strings.HasSuffix(got, "..."), "expected truncation suffix, got %q", got)
	})
	t.Run("no truncation when fits", func(t *testing.T) {
		got := formatLabels(map[string]string{"a": "b"}, 60)
		assert.False(t, strings.HasSuffix(got, "..."), "should not truncate short label: %q", got)
	})
}

func TestFilterByLabels(t *testing.T) {
	items := []NamedItem{
		{Name: "a", Labels: map[string]string{"env": "prod", "rack": "A3"}},
		{Name: "b", Labels: map[string]string{"env": "dev"}},
		{Name: "c", Labels: nil},
		{Name: "d", Labels: map[string]string{"env": "prod", "rack": "B1"}},
	}

	t.Run("no filters", func(t *testing.T) {
		assert.Len(t, filterByLabels(items, nil), 4)
	})
	t.Run("single match", func(t *testing.T) {
		got := filterByLabels(items, map[string]string{"env": "dev"})
		require.Len(t, got, 1)
		assert.Equal(t, "b", got[0].Name)
	})
	t.Run("multi-key AND", func(t *testing.T) {
		got := filterByLabels(items, map[string]string{"env": "prod", "rack": "A3"})
		require.Len(t, got, 1)
		assert.Equal(t, "a", got[0].Name)
	})
	t.Run("no match", func(t *testing.T) {
		assert.Empty(t, filterByLabels(items, map[string]string{"env": "staging"}))
	})
	t.Run("nil labels handled", func(t *testing.T) {
		got := filterByLabels(items, map[string]string{"env": "prod"})
		for _, item := range got {
			assert.NotNil(t, item.Labels, "nil-label item should not pass filter")
		}
	})
}

func TestSortByLabelKey(t *testing.T) {
	t.Run("ascending sort", func(t *testing.T) {
		items := []NamedItem{
			{Name: "c", Labels: map[string]string{"rack": "C1"}},
			{Name: "a", Labels: map[string]string{"rack": "A1"}},
			{Name: "b", Labels: map[string]string{"rack": "B1"}},
		}
		sorted := sortByLabelKey(items, "rack")
		require.Len(t, sorted, 3)
		assert.Equal(t, "a", sorted[0].Name)
		assert.Equal(t, "b", sorted[1].Name)
		assert.Equal(t, "c", sorted[2].Name)
		assert.Equal(t, "c", items[0].Name, "sortByLabelKey must not mutate the original slice")
	})
	t.Run("missing keys sort last", func(t *testing.T) {
		items := []NamedItem{
			{Name: "no-label", Labels: nil},
			{Name: "has-label", Labels: map[string]string{"rack": "A1"}},
		}
		sorted := sortByLabelKey(items, "rack")
		assert.Equal(t, "has-label", sorted[0].Name)
		assert.Equal(t, "no-label", sorted[1].Name)
	})
	t.Run("stable order for equal values", func(t *testing.T) {
		items := []NamedItem{
			{Name: "first", Labels: map[string]string{"rack": "A1"}},
			{Name: "second", Labels: map[string]string{"rack": "A1"}},
		}
		sorted := sortByLabelKey(items, "rack")
		assert.Equal(t, "first", sorted[0].Name)
		assert.Equal(t, "second", sorted[1].Name)
	})
}

func TestParseLabelArgs(t *testing.T) {
	t.Run("label and sort-label", func(t *testing.T) {
		remaining, labels, sortKey, err := parseLabelArgs([]string{"--label", "env=prod", "--sort-label", "rack", "extra"})
		require.NoError(t, err)
		assert.Equal(t, []string{"extra"}, remaining)
		assert.Equal(t, "prod", labels["env"])
		assert.Equal(t, "rack", sortKey)
	})
	t.Run("no label args", func(t *testing.T) {
		remaining, labels, sortKey, err := parseLabelArgs([]string{"foo", "bar"})
		require.NoError(t, err)
		assert.Len(t, remaining, 2)
		assert.Empty(t, labels)
		assert.Empty(t, sortKey)
	})
	t.Run("multiple labels AND", func(t *testing.T) {
		_, labels, _, err := parseLabelArgs([]string{"--label", "env=prod", "--label", "rack=A3"})
		require.NoError(t, err)
		require.Len(t, labels, 2)
		assert.Equal(t, "prod", labels["env"])
		assert.Equal(t, "A3", labels["rack"])
	})
	t.Run("label without equals", func(t *testing.T) {
		_, _, _, err := parseLabelArgs([]string{"--label", "env"})
		assert.Error(t, err)
	})
	t.Run("dangling sort-label", func(t *testing.T) {
		_, _, _, err := parseLabelArgs([]string{"--sort-label"})
		assert.Error(t, err)
	})
	t.Run("dangling label flag", func(t *testing.T) {
		_, _, _, err := parseLabelArgs([]string{"--label"})
		assert.Error(t, err)
	})
	t.Run("conflicting same-key labels", func(t *testing.T) {
		_, _, _, err := parseLabelArgs([]string{"--label", "env=prod", "--label", "env=dev"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicting")
	})
	t.Run("duplicate same-value labels accepted", func(t *testing.T) {
		_, labels, _, err := parseLabelArgs([]string{"--label", "env=prod", "--label", "env=prod"})
		require.NoError(t, err)
		assert.Equal(t, "prod", labels["env"])
	})
}

func TestMergeLabels(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		got, err := mergeLabels(nil, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("conflicting scope and cmd", func(t *testing.T) {
		scope := map[string]string{"env": "dev"}
		cmd := map[string]string{"env": "prod"}
		_, err := mergeLabels(scope, cmd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicts")
	})
	t.Run("same value allowed", func(t *testing.T) {
		scope := map[string]string{"env": "prod"}
		cmd := map[string]string{"env": "prod"}
		got, err := mergeLabels(scope, cmd)
		require.NoError(t, err)
		assert.Equal(t, "prod", got["env"])
	})
	t.Run("combines unique keys", func(t *testing.T) {
		scope := map[string]string{"env": "prod"}
		cmd := map[string]string{"rack": "A3"}
		got, err := mergeLabels(scope, cmd)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "prod", got["env"])
		assert.Equal(t, "A3", got["rack"])
	})
}

func TestPrintLabelHint(t *testing.T) {
	itemsWithLabels := []NamedItem{
		{Name: "m1", Labels: map[string]string{"RackIdentifier": "H19", "ServerName": "pdx01"}},
		{Name: "m2", Labels: map[string]string{"RackIdentifier": "H20"}},
	}
	t.Run("active filter suppresses hint", func(t *testing.T) {
		var buf bytes.Buffer
		printLabelHint(&buf, itemsWithLabels, map[string]string{"RackIdentifier": "H19"})
		assert.Empty(t, buf.String())
	})
	t.Run("no labels means no hint", func(t *testing.T) {
		var buf bytes.Buffer
		printLabelHint(&buf, []NamedItem{{Name: "x"}}, nil)
		assert.Empty(t, buf.String())
	})
	t.Run("whitespace-only label keys do not trigger hint", func(t *testing.T) {
		var buf bytes.Buffer
		items := []NamedItem{{Name: "a", Labels: map[string]string{"": "blank", "  ": "spaces"}}}
		printLabelHint(&buf, items, nil)
		assert.Empty(t, buf.String(), "blank/whitespace keys must not be treated as real labels")
	})
	t.Run("hint uses placeholders not real keys", func(t *testing.T) {
		var buf bytes.Buffer
		printLabelHint(&buf, itemsWithLabels, nil)
		out := buf.String()
		assert.Contains(t, out, "--label <key>=<value>")
		assert.Contains(t, out, "--sort-label <key>")
		assert.Contains(t, out, "scope label <key>=<value>")
		assert.NotContains(t, out, "RackIdentifier", "hint must not surface real keys from the result set")
		assert.NotContains(t, out, "ServerName", "hint must not surface real keys from the result set")
		assert.NotContains(t, out, "Label keys:", "no per-result key listing should be printed")
	})
	t.Run("hint output is exactly one line", func(t *testing.T) {
		var buf bytes.Buffer
		printLabelHint(&buf, itemsWithLabels, nil)
		assert.Equal(t, 1, strings.Count(buf.String(), "\n"), "hint should be a single line")
	})
	t.Run("empty filter map still shows hint", func(t *testing.T) {
		var buf bytes.Buffer
		printLabelHint(&buf, itemsWithLabels, map[string]string{})
		assert.NotEmpty(t, buf.String(), "empty (non-nil) filter map should be treated as no filter")
	})
}

func TestInvalidateFilteredIncludesInstanceType(t *testing.T) {
	c := NewCache()
	c.Set("instance-type", []NamedItem{{Name: "it1", ID: "1"}})
	c.InvalidateFiltered()
	assert.Nil(t, c.Get("instance-type"), "instance-type cache should be invalidated by InvalidateFiltered")
}

func TestAppendScopeFlagsIncludesInstanceType(t *testing.T) {
	s := &Session{
		Scope: Scope{SiteID: "site-1"},
		Cache: NewCache(),
	}
	s.Resolver = NewResolver(s.Cache)
	got := appendScopeFlags(s, []string{"instance-type", "list"})
	assert.True(t, contains(got, "--site-id"), "instance-type should receive --site-id scope flag")
}

func TestVPCFilteringDoesNotMutateCachedSlice(t *testing.T) {
	original := []NamedItem{
		{Name: "m1", ID: "1"},
		{Name: "m2", ID: "2"},
		{Name: "m3", ID: "3"},
	}
	cached := make([]NamedItem, len(original))
	copy(cached, original)

	vpcMembers := map[string]string{"1": "vpc-a"}
	filtered := make([]NamedItem, 0, len(cached))
	for _, item := range cached {
		if _, ok := vpcMembers[item.ID]; ok {
			filtered = append(filtered, item)
		}
	}

	require.Len(t, filtered, 1)
	assert.Equal(t, "m1", filtered[0].Name)
	require.Len(t, cached, 3, "cached slice must not be truncated by filtering")
	assert.Equal(t, "m1", cached[0].Name)
	assert.Equal(t, "m2", cached[1].Name)
	assert.Equal(t, "m3", cached[2].Name)
}

func TestBuildIPBlockCreateBody_UsesAPIFieldNames(t *testing.T) {
	body := buildIPBlockCreateBody(
		"ip-block-0",
		"37c3a99c-f5de-4202-8f46-2e1cc24226f6",
		"7.243.96.128",
		25,
		"IPv4",
		"DatacenterOnly",
	)

	assert.Equal(t, "ip-block-0", body["name"])
	assert.Equal(t, "37c3a99c-f5de-4202-8f46-2e1cc24226f6", body["siteId"])
	assert.Equal(t, "7.243.96.128", body["prefix"])
	assert.Equal(t, 25, body["prefixLength"])
	assert.Equal(t, "IPv4", body["protocolVersion"])
	assert.Equal(t, "DatacenterOnly", body["routingType"])

	_, hasIPVersion := body["ipVersion"]
	assert.False(t, hasIPVersion, "request must not use the legacy ipVersion field")
	_, hasUsageType := body["usageType"]
	assert.False(t, hasUsageType, "request must not use the legacy usageType field")
}

func TestValidateIPBlockPrefixLength(t *testing.T) {
	t.Run("IPv4 in range", func(t *testing.T) {
		require.NoError(t, validateIPBlockPrefixLength("IPv4", 1))
		require.NoError(t, validateIPBlockPrefixLength("IPv4", 25))
		require.NoError(t, validateIPBlockPrefixLength("IPv4", 32))
	})
	t.Run("IPv4 out of range", func(t *testing.T) {
		require.Error(t, validateIPBlockPrefixLength("IPv4", 0))
		require.Error(t, validateIPBlockPrefixLength("IPv4", 33))
	})
	t.Run("IPv6 in range", func(t *testing.T) {
		require.NoError(t, validateIPBlockPrefixLength("IPv6", 1))
		require.NoError(t, validateIPBlockPrefixLength("IPv6", 64))
		require.NoError(t, validateIPBlockPrefixLength("IPv6", 128))
	})
	t.Run("IPv6 out of range", func(t *testing.T) {
		require.Error(t, validateIPBlockPrefixLength("IPv6", 0))
		require.Error(t, validateIPBlockPrefixLength("IPv6", 129))
	})
	t.Run("unsupported protocol", func(t *testing.T) {
		require.Error(t, validateIPBlockPrefixLength("IPv5", 16))
	})
}

func TestPromptChoice(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		got, err := withStdin(t, "IPv6\n", func() (string, error) {
			return PromptChoice("Protocol", []string{"IPv4", "IPv6"}, "IPv4")
		})
		require.NoError(t, err)
		assert.Equal(t, "IPv6", got)
	})
	t.Run("case insensitive returns canonical", func(t *testing.T) {
		got, err := withStdin(t, "datacenteronly\n", func() (string, error) {
			return PromptChoice("Routing", []string{"DatacenterOnly", "Public"}, "")
		})
		require.NoError(t, err)
		assert.Equal(t, "DatacenterOnly", got)
	})
	t.Run("empty uses default", func(t *testing.T) {
		got, err := withStdin(t, "\n", func() (string, error) {
			return PromptChoice("Protocol", []string{"IPv4", "IPv6"}, "IPv4")
		})
		require.NoError(t, err)
		assert.Equal(t, "IPv4", got)
	})
	t.Run("retries invalid input then accepts valid", func(t *testing.T) {
		got, err := withStdin(t, "nope\nIPv4\n", func() (string, error) {
			return PromptChoice("Protocol", []string{"IPv4", "IPv6"}, "")
		})
		require.NoError(t, err)
		assert.Equal(t, "IPv4", got)
	})
	t.Run("rejects default not in options", func(t *testing.T) {
		_, err := withStdin(t, "\n", func() (string, error) {
			return PromptChoice("Protocol", []string{"IPv4", "IPv6"}, "IPv5")
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in allowed options")
	})
}

// withStdin pipes the provided input into os.Stdin for the duration of f,
// captures stdout so the prompt text does not leak into test output, and
// restores both when it returns. All four pipe ends are closed before
// returning so repeated test runs do not accumulate file descriptors.
func withStdin(t *testing.T, input string, f func() (string, error)) (string, error) {
	t.Helper()
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	sr, sw, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	os.Stdout = sw
	defer func() {
		_ = r.Close()
		_ = sr.Close()
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()
	go func() {
		defer w.Close()
		_, _ = io.WriteString(w, input)
	}()
	result, rerr := f()
	_ = sw.Close()
	_, _ = io.Copy(io.Discard, sr)
	return result, rerr
}

// --- Lifecycle and task command tests ---

func TestTaskIDFromArgsOrPrompt_ArgWins(t *testing.T) {
	got, err := taskIDFromArgsOrPrompt([]string{"  abc-123  "}, "Task ID")
	require.NoError(t, err)
	assert.Equal(t, "abc-123", got)
}

func TestTaskIDFromArgsOrPrompt_PromptsWhenNoArg(t *testing.T) {
	got, err := withStdin(t, "task-from-prompt\n", func() (string, error) {
		return taskIDFromArgsOrPrompt(nil, "Task ID")
	})
	require.NoError(t, err)
	assert.Equal(t, "task-from-prompt", got)
}

func TestTaskIDFromArgsOrPrompt_RejectsEmptyArg(t *testing.T) {
	got, err := withStdin(t, "\n", func() (string, error) {
		return taskIDFromArgsOrPrompt([]string{"   "}, "Task ID")
	})
	require.Error(t, err)
	assert.Empty(t, got)
}

func TestPrintTaskIDs_PrintsFromTaskIDsResponse(t *testing.T) {
	body := []byte(`{"taskIds":["t1","t2","t3"],"siteId":"s-1"}`)
	out := captureStdout(func() {
		_ = printTaskIDs(body, "Rack power")
	})
	assert.Contains(t, out, "Rack power started; 3 task(s):")
	assert.Contains(t, out, "t1")
	assert.Contains(t, out, "t2")
	assert.Contains(t, out, "t3")
	assert.Contains(t, out, `"taskIds"`)
}

func TestPrintTaskIDs_HandlesEmptyTaskIDs(t *testing.T) {
	body := []byte(`{"taskIds":[]}`)
	out := captureStdout(func() {
		_ = printTaskIDs(body, "Rack bringup")
	})
	assert.NotContains(t, out, "started")
	assert.Contains(t, out, `"taskIds"`)
}

func TestPowerStateChoices_MatchOpenAPI(t *testing.T) {
	expected := []string{"on", "off", "cycle", "forceoff", "forcecycle"}
	assert.Equal(t, expected, powerStateChoices,
		"powerStateChoices must match UpdatePowerStateRequest.state enum from openapi/spec.yaml")
}

func TestAllCommands_HasLifecycleAndTaskCommands(t *testing.T) {
	commands := AllCommands()
	names := make(map[string]bool, len(commands))
	for _, cmd := range commands {
		names[cmd.Name] = true
	}
	want := []string{
		"tray list", "tray get",
		"tray power", "tray firmware", "tray validate",
		"rack bringup", "rack power", "rack firmware", "rack validate",
		"rack task get", "rack task cancel",
	}
	for _, n := range want {
		assert.True(t, names[n], "expected command %q to be registered", n)
	}
}

func TestRequireSiteScope_ReturnsExistingScope(t *testing.T) {
	s := &Session{
		Scope: Scope{SiteID: "site-existing", SiteName: "existing"},
		Cache: NewCache(),
	}
	got, err := requireSiteScope(s, "should not prompt")
	require.NoError(t, err)
	assert.Equal(t, "site-existing", got)
}

// --- Machine health alert tests ---

func TestExtractBlockingAlerts_FiltersByPreventAllocations(t *testing.T) {
	raw := map[string]interface{}{
		"health": map[string]interface{}{
			"alerts": []interface{}{
				map[string]interface{}{
					"id":              "BmcExplorationFailure",
					"target":          "10.91.54.118",
					"message":         "Redfish endpoint refused connection",
					"classifications": []interface{}{"PreventAllocations"},
				},
				map[string]interface{}{
					"id":              "FanSpeed",
					"target":          "Fan1A",
					"message":         "Fan running slow",
					"classifications": []interface{}{"Informational"},
				},
				map[string]interface{}{
					"id":              "FailedValidationTest",
					"target":          "DcgmFullShort",
					"message":         "Failed validation",
					"classifications": []interface{}{"PreventAllocations", "ValidationFailure"},
				},
			},
		},
	}
	alerts := extractBlockingAlerts(raw)
	require.Len(t, alerts, 2)
	assert.Equal(t, "BmcExplorationFailure", alerts[0].ID)
	assert.Equal(t, "10.91.54.118", alerts[0].Target)
	assert.Equal(t, "FailedValidationTest", alerts[1].ID)
}

func TestExtractBlockingAlerts_EmptyHealth(t *testing.T) {
	cases := []struct {
		name string
		raw  interface{}
	}{
		{"nil", nil},
		{"non-map", "not a map"},
		{"missing health", map[string]interface{}{"id": "machine-1"}},
		{"non-map health", map[string]interface{}{"health": "broken"}},
		{"missing alerts", map[string]interface{}{"health": map[string]interface{}{}}},
		{"non-array alerts", map[string]interface{}{"health": map[string]interface{}{"alerts": "x"}}},
		{"empty alerts", map[string]interface{}{"health": map[string]interface{}{"alerts": []interface{}{}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Empty(t, extractBlockingAlerts(tc.raw))
		})
	}
}

func TestSummarizeBlockingAlert(t *testing.T) {
	cases := []struct {
		name string
		raw  interface{}
		want string
	}{
		{
			name: "no alerts",
			raw:  map[string]interface{}{},
			want: "",
		},
		{
			name: "id and concise target",
			raw: map[string]interface{}{
				"health": map[string]interface{}{
					"alerts": []interface{}{
						map[string]interface{}{
							"id":              "BmcExplorationFailure",
							"target":          "10.91.54.118",
							"classifications": []interface{}{"PreventAllocations"},
						},
					},
				},
			},
			want: "BmcExplorationFailure 10.91.54.118",
		},
		{
			name: "id only when target empty",
			raw: map[string]interface{}{
				"health": map[string]interface{}{
					"alerts": []interface{}{
						map[string]interface{}{
							"id":              "FailedValidationTest",
							"classifications": []interface{}{"PreventAllocations"},
						},
					},
				},
			},
			want: "FailedValidationTest",
		},
		{
			name: "long target gets truncated",
			raw: map[string]interface{}{
				"health": map[string]interface{}{
					"alerts": []interface{}{
						map[string]interface{}{
							"id":              "X",
							"target":          strings.Repeat("a", 50),
							"classifications": []interface{}{"PreventAllocations"},
						},
					},
				},
			},
			want: "X " + strings.Repeat("a", 21) + "...",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, summarizeBlockingAlert(tc.raw))
		})
	}
}

func TestPrintMachineHealthSummary_PrintsBlockingAlerts(t *testing.T) {
	body := []byte(`{
		"id": "machine-1",
		"status": "Error",
		"isUsableByTenant": false,
		"health": {
			"alerts": [
				{
					"id": "BmcExplorationFailure",
					"target": "10.91.54.118",
					"message": "Failed to connect to Redfish endpoint at 10.91.54.118\nadditional context",
					"classifications": ["PreventAllocations"]
				}
			]
		}
	}`)
	var buf bytes.Buffer
	printMachineHealthSummary(&buf, body)
	out := buf.String()
	assert.Contains(t, out, "Blocking health alerts:")
	assert.Contains(t, out, "BmcExplorationFailure")
	assert.Contains(t, out, "10.91.54.118")
	assert.Contains(t, out, "PreventAllocations")
	assert.Contains(t, out, "Status: Error")
	assert.Contains(t, out, "Usable by tenant: false")
	assert.Contains(t, out, "Failed to connect")
	assert.Contains(t, out, "(...)")
}

func TestPrintMachineHealthSummary_SuppressedForHealthyMachine(t *testing.T) {
	body := []byte(`{"id": "machine-1", "status": "Ready", "health": {"alerts": []}}`)
	var buf bytes.Buffer
	printMachineHealthSummary(&buf, body)
	assert.Empty(t, buf.String())
}

func TestPrintMachineHealthSummary_SuppressedForNonPreventAllocations(t *testing.T) {
	body := []byte(`{
		"status": "Ready",
		"health": {"alerts": [
			{"id": "FanSpeed", "target": "Fan1A", "classifications": ["Informational"]}
		]}
	}`)
	var buf bytes.Buffer
	printMachineHealthSummary(&buf, body)
	assert.Empty(t, buf.String())
}

func TestShortMessage(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"single line", "single line"},
		{"  trimmed  ", "trimmed"},
		{"first\nsecond\nthird", "first (...)"},
		{"\nfirst non-empty\nsecond", "first non-empty (...)"},
		{strings.Repeat("a", 250), strings.Repeat("a", 197) + "..."},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, shortMessage(tc.in))
		})
	}
}

// --- Helpers ---

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(ss []string, target string) bool {
	i := sort.SearchStrings(ss, target)
	if i < len(ss) && ss[i] == target {
		return true
	}
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// --- Allocation create tests ---

func TestBuildTenantSelectItems_MapsTenantIDAndAppendsManualSentinel(t *testing.T) {
	accounts := []NamedItem{
		{
			Name:   "acme",
			ID:     "account-1",
			Status: "Active",
			Extra:  map[string]string{"tenantId": "tenant-1", "tenantOrg": "acme"},
		},
		{
			Name:  "globex",
			ID:    "account-2",
			Extra: map[string]string{"tenantId": "tenant-2"},
		},
	}

	items := buildTenantSelectItems(accounts, "", "")

	require.Len(t, items, 3, "two tenants plus the manual-entry sentinel")
	assert.Equal(t, "tenant-1", items[0].ID, "select ID must be the tenantId, not the tenant-account ID")
	assert.Contains(t, items[0].Label, "acme")
	assert.Contains(t, items[0].Label, "Active", "status should be surfaced in the label")
	assert.Equal(t, "tenant-2", items[1].ID)
	assert.Equal(t, tenantManualEntrySentinel, items[2].ID)
}

func TestBuildTenantSelectItems_SkipsAccountsWithoutTenantID(t *testing.T) {
	accounts := []NamedItem{
		{Name: "pending-invite", ID: "account-1", Extra: map[string]string{"tenantId": ""}},
		{Name: "no-extra", ID: "account-2"},
	}

	items := buildTenantSelectItems(accounts, "", "")

	assert.Nil(t, items, "accounts without a tenantId must be skipped and no sentinel emitted")
}

func TestBuildTenantSelectItems_EmptyInputReturnsNil(t *testing.T) {
	assert.Nil(t, buildTenantSelectItems(nil, "", ""))
	assert.Nil(t, buildTenantSelectItems([]NamedItem{}, "", ""))
}

func TestBuildTenantSelectItems_FallsBackToTenantIDWhenNameBlank(t *testing.T) {
	accounts := []NamedItem{
		{Name: "   ", Extra: map[string]string{"tenantId": "tenant-xyz"}},
	}
	items := buildTenantSelectItems(accounts, "", "")
	require.Len(t, items, 2)
	assert.Equal(t, "tenant-xyz", items[0].Label)
}

func TestBuildTenantSelectItems_DisambiguatesDuplicateLabels(t *testing.T) {
	// Two distinct tenants with the same display name (e.g. "test-org" in
	// dev envs) must not produce visually identical picker options, because
	// the user could route the allocation to the wrong tenant.
	accounts := []NamedItem{
		{Name: "test-org", Extra: map[string]string{"tenantId": "11111111-aaaa-bbbb-cccc-1111aaaa0001"}},
		{Name: "test-org", Extra: map[string]string{"tenantId": "22222222-aaaa-bbbb-cccc-2222aaaa0002"}},
		{Name: "unique", Extra: map[string]string{"tenantId": "33333333-aaaa-bbbb-cccc-3333aaaa0003"}},
	}
	items := buildTenantSelectItems(accounts, "", "")
	require.Len(t, items, 4, "three tenants plus the manual-entry sentinel")

	labels := []string{items[0].Label, items[1].Label, items[2].Label}
	for _, l := range labels {
		count := 0
		for _, l2 := range labels {
			if l == l2 {
				count++
			}
		}
		assert.Equal(t, 1, count, "label %q must be unique after disambiguation, got %d copies", l, count)
	}

	uniqueIdx := -1
	for i, it := range items[:3] {
		if it.ID == "33333333-aaaa-bbbb-cccc-3333aaaa0003" {
			uniqueIdx = i
		}
	}
	require.NotEqual(t, -1, uniqueIdx)
	assert.Equal(t, "unique", items[uniqueIdx].Label,
		"items whose label is already unique must NOT get a disambiguating suffix")
}

func TestShortTenantID(t *testing.T) {
	assert.Equal(t, "short", shortTenantID("short"))
	assert.Equal(t, "12345678", shortTenantID("12345678"))
	assert.Equal(t, "ddccbbaa", shortTenantID("11111111-aaaa-bbbb-cccc-ddddccbbaa"),
		"long UUID must return last 8 chars only")
}

func TestBuildTenantSelectItems_SortsAlphabeticallyByLabel(t *testing.T) {
	accounts := []NamedItem{
		{Name: "zeta", Extra: map[string]string{"tenantId": "tenant-z"}},
		{Name: "alpha", Extra: map[string]string{"tenantId": "tenant-a"}},
		{Name: "mu", Extra: map[string]string{"tenantId": "tenant-m"}},
	}
	items := buildTenantSelectItems(accounts, "", "")
	require.Len(t, items, 4)
	assert.Equal(t, "alpha", items[0].Label)
	assert.Equal(t, "mu", items[1].Label)
	assert.Equal(t, "zeta", items[2].Label)
	assert.Equal(t, tenantManualEntrySentinel, items[3].ID, "manual-entry sentinel must stay last")
}

func TestBuildTenantSelectItems_SortTieBreaksByID(t *testing.T) {
	accounts := []NamedItem{
		{Name: "acme", Extra: map[string]string{"tenantId": "tenant-b"}},
		{Name: "acme", Extra: map[string]string{"tenantId": "tenant-a"}},
	}
	items := buildTenantSelectItems(accounts, "", "")
	require.Len(t, items, 3)
	assert.Equal(t, "tenant-a", items[0].ID, "equal labels must tie-break by ID")
	assert.Equal(t, "tenant-b", items[1].ID)
}

func TestBuildTenantSelectItems_DeduplicatesByTenantID(t *testing.T) {
	accounts := []NamedItem{
		{Name: "acme-prod", Extra: map[string]string{"tenantId": "tenant-1"}},
		{Name: "acme-dev", Extra: map[string]string{"tenantId": "tenant-1"}},
		{Name: "globex", Extra: map[string]string{"tenantId": "tenant-2"}},
	}

	items := buildTenantSelectItems(accounts, "", "")

	require.Len(t, items, 3, "two unique tenants plus the manual-entry sentinel")
	assert.Equal(t, "tenant-1", items[0].ID)
	assert.Equal(t, "acme-prod", items[0].Label, "first occurrence wins on dedupe")
	assert.Equal(t, "tenant-2", items[1].ID)
	assert.Equal(t, tenantManualEntrySentinel, items[2].ID)
}

func TestBuildTenantSelectItems_SelfTenantPinnedFirstWithSuffix(t *testing.T) {
	// Common dev-cluster case: caller is both Provider Admin and Tenant
	// Admin for the same org, so there are zero tenant-accounts but their
	// own tenant id is known. Must appear as the first picker entry with
	// a "(self)" suffix so the label is unambiguous.
	items := buildTenantSelectItems(nil, "11111111-2222-3333-4444-555566667777", "nico")
	require.Len(t, items, 2, "self entry plus manual-entry sentinel")
	assert.Equal(t, "11111111-2222-3333-4444-555566667777", items[0].ID)
	assert.Equal(t, "nico (self)", items[0].Label)
	assert.Equal(t, tenantManualEntrySentinel, items[1].ID)
}

func TestBuildTenantSelectItems_SelfTenantBlankOrgFallsBackToID(t *testing.T) {
	items := buildTenantSelectItems(nil, "abc-tenant-id", "   ")
	require.Len(t, items, 2)
	assert.Equal(t, "abc-tenant-id (self)", items[0].Label,
		"blank org name must fall back to the tenant id so the label is still non-empty")
}

func TestBuildTenantSelectItems_SelfTenantStaysFirstWhenAccountsSort(t *testing.T) {
	accounts := []NamedItem{
		{Name: "zeta", Extra: map[string]string{"tenantId": "tenant-z"}},
		{Name: "alpha", Extra: map[string]string{"tenantId": "tenant-a"}},
	}
	items := buildTenantSelectItems(accounts, "self-tenant", "nico")
	require.Len(t, items, 4, "self + 2 tenant-accounts + sentinel")
	assert.Equal(t, "nico (self)", items[0].Label, "self always pinned first even if it sorts after")
	assert.Equal(t, "alpha", items[1].Label, "remaining items sort alphabetically")
	assert.Equal(t, "zeta", items[2].Label)
	assert.Equal(t, tenantManualEntrySentinel, items[3].ID)
}

func TestBuildTenantSelectItems_SelfTenantDedupesWithAccount(t *testing.T) {
	// If a tenant-account already references the same tenant id as self,
	// only the self entry is shown (inserted first, so the account-row
	// copy is dropped by the dedupe map).
	accounts := []NamedItem{
		{Name: "nico", Extra: map[string]string{"tenantId": "self-tenant"}},
	}
	items := buildTenantSelectItems(accounts, "self-tenant", "nico")
	require.Len(t, items, 2, "one entry (self) plus manual-entry sentinel")
	assert.Equal(t, "nico (self)", items[0].Label)
	assert.Equal(t, "self-tenant", items[0].ID)
}

func TestBuildTenantSelectItems_EmptySelfTenantIgnored(t *testing.T) {
	items := buildTenantSelectItems(nil, "", "nico")
	assert.Nil(t, items, "no self id and no accounts means no picker")
}

func TestAllocationConstraintResourceTypes_MatchAPIValidation(t *testing.T) {
	items := allocationConstraintResourceTypes()
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	assert.ElementsMatch(t, []string{"IPBlock", "InstanceType"}, ids,
		"resource type IDs must match APIAllocationConstraintCreateRequest validation")
}

func TestAllocationConstraintTypes_OnlyExposesReserved(t *testing.T) {
	items := allocationConstraintTypes()
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	assert.Equal(t, []string{"Reserved"}, ids,
		"only Reserved is offered; OnDemand/Preemptible are accepted by the API validator "+
			"but are documented as unsupported by the current backend implementation")
}

func TestResolverResourceForAllocationResourceType(t *testing.T) {
	cases := []struct {
		resourceType string
		wantKey      string
		wantLabel    string
		wantOK       bool
	}{
		{"IPBlock", "ip-block", "IP Block", true},
		{"InstanceType", "instance-type", "Instance Type", true},
		{"Unknown", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.resourceType, func(t *testing.T) {
			key, label, ok := resolverResourceForAllocationResourceType(tc.resourceType)
			assert.Equal(t, tc.wantKey, key)
			assert.Equal(t, tc.wantLabel, label)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestBuildAllocationConstraint_ValidInput(t *testing.T) {
	got, err := buildAllocationConstraint("IPBlock", "block-1", "Reserved", "  28 ")
	require.NoError(t, err)
	assert.Equal(t, "IPBlock", got["resourceType"])
	assert.Equal(t, "block-1", got["resourceTypeId"])
	assert.Equal(t, "Reserved", got["constraintType"])
	assert.Equal(t, 28, got["constraintValue"], "value must be an int, not a string")
}

func TestBuildAllocationConstraint_RejectsNonInteger(t *testing.T) {
	_, err := buildAllocationConstraint("IPBlock", "block-1", "Reserved", "not-a-number")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "integer")
}

func TestBuildAllocationConstraint_RejectsOutOfRangeIPBlockPrefix(t *testing.T) {
	_, err := buildAllocationConstraint("IPBlock", "block-1", "Reserved", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prefix length")

	_, err = buildAllocationConstraint("IPBlock", "block-1", "Reserved", "33")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prefix length")
}

func TestBuildAllocationConstraint_AcceptsBoundaryIPBlockPrefix(t *testing.T) {
	_, err := buildAllocationConstraint("IPBlock", "block-1", "Reserved", "1")
	require.NoError(t, err)
	_, err = buildAllocationConstraint("IPBlock", "block-1", "Reserved", "32")
	require.NoError(t, err)
}

func TestBuildAllocationConstraint_RejectsNonPositiveInstanceTypeCount(t *testing.T) {
	_, err := buildAllocationConstraint("InstanceType", "type-1", "Reserved", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1")

	_, err = buildAllocationConstraint("InstanceType", "type-1", "Reserved", "-5")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1")
}

func TestBuildAllocationConstraint_MarshalShape(t *testing.T) {
	c, err := buildAllocationConstraint("InstanceType", "type-1", "Reserved", "4")
	require.NoError(t, err)
	encoded, err := json.Marshal(c)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, "InstanceType", decoded["resourceType"])
	assert.Equal(t, "type-1", decoded["resourceTypeId"])
	assert.Equal(t, "Reserved", decoded["constraintType"])
	assert.InDelta(t, 4, decoded["constraintValue"], 0.0001,
		"constraintValue must round-trip through JSON as a number, not a string")
}

func TestAllocationConstraintValueHint(t *testing.T) {
	assert.Contains(t, allocationConstraintValueHint("IPBlock"), "prefix")
	assert.Contains(t, allocationConstraintValueHint("InstanceType"), "machine")
	assert.NotEmpty(t, allocationConstraintValueHint("Unknown"), "unknown types still get a generic hint")
}

// --- VPC prefix create IP block picker tests (NVBug 6105076) ---

func TestBuildIPBlockSelectItems_MapsBlocksAndAppendsManualSentinel(t *testing.T) {
	blocks := []NamedItem{
		{Name: "block-a", ID: "id-a", Status: "Ready"},
		{Name: "block-b", ID: "id-b"},
	}

	items := buildIPBlockSelectItems(blocks)

	require.Len(t, items, 3, "two IP blocks plus the manual-entry sentinel")
	assert.Equal(t, "id-a", items[0].ID, "select ID must be the IP block UUID")
	assert.Contains(t, items[0].Label, "block-a")
	assert.Contains(t, items[0].Label, "Ready", "status should be surfaced in the label")
	assert.Equal(t, "id-b", items[1].ID)
	assert.Equal(t, ipBlockManualEntrySentinel, items[2].ID)
}

func TestBuildIPBlockSelectItems_EmptyListReturnsOnlySentinel(t *testing.T) {
	items := buildIPBlockSelectItems(nil)
	require.Len(t, items, 1, "an empty list still offers manual entry")
	assert.Equal(t, ipBlockManualEntrySentinel, items[0].ID)
}

func TestBuildIPBlockSelectItems_SkipsBlocksWithoutIDAndFallsBackLabelToID(t *testing.T) {
	blocks := []NamedItem{
		{Name: "no-id", ID: "  "},
		{Name: "  ", ID: "id-x"},
	}

	items := buildIPBlockSelectItems(blocks)

	require.Len(t, items, 2, "one usable block (id-x) plus the manual-entry sentinel")
	assert.Equal(t, "id-x", items[0].ID)
	assert.Equal(t, "id-x", items[0].Label, "blank name must fall back to the ID")
	assert.Equal(t, ipBlockManualEntrySentinel, items[1].ID)
}
