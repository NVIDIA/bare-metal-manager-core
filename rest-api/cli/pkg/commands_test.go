// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NVIDIA/infra-controller-rest/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v2"
)

func TestToKebab(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Space-separated (tag names)
		{"Site", "site"},
		{"IP Block", "ip-block"},
		{"SSH Key Group", "ssh-key-group"},
		{"DPU Extension Service", "dpu-extension-service"},
		{"Infrastructure Provider", "infrastructure-provider"},
		{"NVLink Logical Partition", "nvlink-logical-partition"},

		// CamelCase (parameter and field names)
		{"siteId", "site-id"},
		{"pageNumber", "page-number"},
		{"pageSize", "page-size"},
		{"infrastructureProviderId", "infrastructure-provider-id"},
		{"networkSecurityGroupId", "network-security-group-id"},
		{"serialConsoleHostname", "serial-console-hostname"},

		// Acronym handling
		{"NVLinkLogicalPartition", "nvlink-logical-partition"},
		{"isNVLinkPartitionEnabled", "is-nvlink-partition-enabled"},
		{"dpuExtensionServiceId", "dpu-extension-service-id"},

		// Already lowercase
		{"site", "site"},
		{"org", "org"},

		// Single word uppercase
		{"ID", "id"},
		{"VPC", "vpc"},
		{"SKU", "sku"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := toKebab(tt.input)
			if got != tt.want {
				t.Errorf("toKebab(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClientFromContextExplicitTokenCommandOverridesCachedConfigToken(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &ConfigFile{
		API: ConfigAPI{
			Base: "http://localhost:8388",
			Org:  "test-org",
		},
		Auth: ConfigAuth{
			Token: "cached-token",
		},
	}
	require.NoError(t, SaveConfigToPath(cfg, configPath))
	SetConfigPath(configPath)
	defer SetConfigPath("")

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.String("token", "", "")
	flags.String("token-command", "", "")
	flags.String("base-url", "", "")
	flags.String("org", "", "")
	flags.Bool("debug", false, "")
	require.NoError(t, flags.Set("token-command", "printf explicit-token"))

	ctx := cli.NewContext(cli.NewApp(), flags, nil)
	client, err := clientFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, "explicit-token", client.Token)
}

func TestOperationAction(t *testing.T) {
	tests := []struct {
		opID string
		want string
	}{
		{"get-all-site", "list"},
		{"get-all-instance", "list"},
		{"get-all-allocation-constraint", "list"},
		{"get-current-infrastructure-provider", "get"},
		{"get-current-tenant", "get"},
		{"get-current-service-account", "get"},
		{"create-site", "create"},
		{"create-allocation-constraint", "create"},
		{"update-site", "update"},
		{"delete-site", "delete"},
		{"get-site", "get"},
		{"get-allocation", "get"},
		{"get-site-status-history", "status-history"},
		{"get-instance-status-history", "status-history"},
		{"get-machine-status-history", "status-history"},
		// get-current-* matches before -stats suffix check
		{"get-current-infrastructure-provider-stats", "get"},
		{"get-current-tenant-stats", "get"},
		{"batch-create-instance", "batch-create"},
		{"batch-create-expected-machines", "batch-create"},
		{"batch-update-expected-machines", "batch-update"},
		{"get-metadata", "get"},
		{"get-user", "get"},
		{"update-identity-config", "update"},
		{"get-identity-config", "get"},
		{"delete-identity-config", "delete"},
		{"update-token-delegation", "update"},
		{"get-token-delegation", "get"},
		{"delete-token-delegation", "delete"},
		{"get-jwks", "get"},
		{"get-spiffe-jwks", "get"},
		{"get-openid-configuration", "get"},
	}

	for _, tt := range tests {
		t.Run(tt.opID, func(t *testing.T) {
			got := operationAction(tt.opID)
			if got != tt.want {
				t.Errorf("operationAction(%q) = %q, want %q", tt.opID, got, tt.want)
			}
		})
	}
}

func TestExtractResourceSuffix(t *testing.T) {
	tests := []struct {
		opID string
		want string
	}{
		{"get-all-site", "site"},
		{"create-site", "site"},
		{"get-site", "site"},
		{"delete-site", "site"},
		{"update-site", "site"},
		{"get-all-allocation-constraint", "allocation-constraint"},
		{"get-current-infrastructure-provider", "infrastructure-provider"},
		{"batch-create-expected-machines", "expected-machines"},
		{"batch-update-expected-machines", "expected-machines"},
		{"get-site-status-history", "site-status-history"},
		{"get-instance-status-history", "instance-status-history"},
		{"update-identity-config", "identity-config"},
		{"get-identity-config", "identity-config"},
		{"delete-identity-config", "identity-config"},
		{"update-token-delegation", "token-delegation"},
		{"get-token-delegation", "token-delegation"},
		{"delete-token-delegation", "token-delegation"},
		{"get-jwks", "jwks"},
		{"get-spiffe-jwks", "spiffe-jwks"},
		{"get-openid-configuration", "openid-configuration"},
	}

	for _, tt := range tests {
		t.Run(tt.opID, func(t *testing.T) {
			got := extractResourceSuffix(tt.opID)
			if got != tt.want {
				t.Errorf("extractResourceSuffix(%q) = %q, want %q", tt.opID, got, tt.want)
			}
		})
	}
}

func TestSubResourceName(t *testing.T) {
	tests := []struct {
		suffix  string
		primary string
		want    string
	}{
		// Exact match → primary
		{"site", "site", ""},
		{"allocation", "allocation", ""},
		{"instance", "instance", ""},

		// Plural match → primary
		{"expected-machines", "expected-machine", ""},

		// Primary as prefix → sub-resource
		{"allocation-constraint", "allocation", "constraint"},
		{"dpu-extension-service-version", "dpu-extension-service", "version"},
		{"instance-type-machine-association", "instance-type", "machine-association"},

		// Action modifiers → primary (not sub-resource)
		{"site-status-history", "site", ""},
		{"instance-status-history", "instance", ""},
		{"infrastructure-provider-stats", "infrastructure-provider", ""},

		// Primary as suffix → sub-resource
		{"derived-ipblock", "ipblock", "derived"},

		// No overlap → sub-resource (full suffix)
		{"interface", "instance", "interface"},
		{"infiniband-interface", "instance", "infiniband-interface"},
		{"nvlink-interface", "nvlink-logical-partition", "nvlink-interface"},
	}

	for _, tt := range tests {
		name := tt.suffix + "_primary_" + tt.primary
		t.Run(name, func(t *testing.T) {
			got := subResourceName(tt.suffix, tt.primary)
			if got != tt.want {
				t.Errorf("subResourceName(%q, %q) = %q, want %q", tt.suffix, tt.primary, got, tt.want)
			}
		})
	}
}

func TestDetectPrimaryResource(t *testing.T) {
	tests := []struct {
		name  string
		opIDs []string
		want  string
	}{
		{
			name: "site is primary",
			opIDs: []string{
				"get-all-site", "create-site", "get-site", "update-site", "delete-site",
				"get-site-status-history",
			},
			want: "site",
		},
		{
			name: "allocation wins over allocation-constraint by shorter length on tie",
			opIDs: []string{
				"get-all-allocation", "create-allocation", "get-allocation", "update-allocation", "delete-allocation",
				"get-all-allocation-constraint", "create-allocation-constraint", "get-allocation-constraint", "update-allocation-constraint", "delete-allocation-constraint",
			},
			want: "allocation",
		},
		{
			name: "instance wins with more operations",
			opIDs: []string{
				"get-all-instance", "create-instance", "get-instance", "update-instance", "delete-instance",
				"batch-create-instance", "get-instance-status-history",
				"get-all-interface",
				"get-all-infiniband-interface",
			},
			want: "instance",
		},
		{
			name: "expected-machine with plural batch ops",
			opIDs: []string{
				"create-expected-machine", "get-all-expected-machine", "get-expected-machine",
				"update-expected-machine", "delete-expected-machine",
				"batch-create-expected-machines", "batch-update-expected-machines",
			},
			want: "expected-machine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := make([]resolvedOp, len(tt.opIDs))
			for i, opID := range tt.opIDs {
				ops[i] = resolvedOp{
					op: &Operation{OperationID: opID},
				}
			}
			got := detectPrimaryResource(ops)
			if got != tt.want {
				t.Errorf("detectPrimaryResource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCoerceValue(t *testing.T) {
	tests := []struct {
		value      string
		schemaType SchemaType
		want       interface{}
		wantErr    bool
	}{
		// Integers
		{"42", "integer", 42, false},
		{"0", "integer", 0, false},
		{"-1", "integer", -1, false},
		{"abc", "integer", nil, true},

		// Booleans
		{"true", "boolean", true, false},
		{"false", "boolean", false, false},
		{"1", "boolean", true, false},
		{"0", "boolean", false, false},
		{"yes", "boolean", nil, true},

		// Numbers (float)
		{"3.14", "number", 3.14, false},
		{"0", "number", float64(0), false},
		{"abc", "number", nil, true},

		// Strings (passthrough)
		{"hello", "string", "hello", false},
		{"", "string", "", false},
		{"123", "string", "123", false},
	}

	for _, tt := range tests {
		name := string(tt.schemaType) + "_" + tt.value
		t.Run(name, func(t *testing.T) {
			got, err := coerceValue(tt.value, tt.schemaType)
			if (err != nil) != tt.wantErr {
				t.Errorf("coerceValue(%q, %q) error = %v, wantErr %v", tt.value, tt.schemaType, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("coerceValue(%q, %q) = %v (%T), want %v (%T)", tt.value, tt.schemaType, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestIsListAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"list", true},
		{"list-interfaces", true},
		{"list-infiniband-interfaces", true},
		{"get", false},
		{"create", false},
		{"delete", false},
		{"listing", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := isListAction(tt.action)
			if got != tt.want {
				t.Errorf("isListAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

// TestBuildCommands_NoDuplicateFlags walks every command produced from the
// embedded OpenAPI spec and asserts that no single command declares the same
// flag name twice. Duplicate names cause urfave/cli to panic at
// flag.(*FlagSet).Var ("flag redefined") when the command's flag set is built,
// which is exactly how the dpu-extension-service create bug surfaced.
func TestBuildCommands_NoDuplicateFlags(t *testing.T) {
	spec, err := ParseSpec(openapi.Spec)
	require.NoError(t, err, "ParseSpec failed")

	cmds := BuildCommands(spec)
	require.NotEmpty(t, cmds, "BuildCommands returned no commands")

	var visit func(path string, children []*cli.Command)
	visit = func(path string, children []*cli.Command) {
		for _, c := range children {
			full := path + " " + c.Name
			seen := make(map[string]bool)
			for _, f := range c.Flags {
				name := f.Names()[0]
				assert.Falsef(t, seen[name],
					"command %q declares duplicate flag %q (would panic at runtime)", full, name)
				seen[name] = true
			}
			if len(c.Subcommands) > 0 {
				visit(full, c.Subcommands)
			}
		}
	}
	visit("nicocli", cmds)
}

// TestBuildActionCommand_ReservedBodyPropertyPrefixed verifies that when a
// request body schema has a property whose kebab-cased name collides with a
// reserved CLI-wrapper flag (data, data-file, output, all), the generated
// command registers the body property under a "body-" prefix instead of
// creating a duplicate flag.
func TestBuildActionCommand_ReservedBodyPropertyPrefixed(t *testing.T) {
	spec := &Spec{
		Paths: map[string]PathItem{
			"/v2/org/{org}/nico/widget": {
				Post: &Operation{
					OperationID: "create-widget",
					Tags:        []string{"Widget"},
					RequestBody: &RequestBody{
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type: "object",
									Properties: map[string]*Schema{
										"name":     {Type: "string"},
										"data":     {Type: "string"},
										"dataFile": {Type: "string"},
										"output":   {Type: "string"},
										"all":      {Type: "boolean"},
									},
									Required: []string{"name"},
								},
							},
						},
					},
				},
			},
		},
	}

	ro := resolvedOp{
		tag:    "Widget",
		action: "create",
		method: "POST",
		path:   "/v2/org/{org}/nico/widget",
		op:     spec.Paths["/v2/org/{org}/nico/widget"].Post,
	}

	cmd := buildActionCommand(spec, ro, "")

	counts := make(map[string]int)
	for _, f := range cmd.Flags {
		counts[f.Names()[0]]++
	}

	// Wrapper flags stay unprefixed with exactly one registration each.
	assert.Equal(t, 1, counts["data"], "--data (JSON wrapper)")
	assert.Equal(t, 1, counts["data-file"], "--data-file (JSON wrapper)")
	assert.Equal(t, 1, counts["output"], "--output (format flag)")

	// --all is list-only; on a create action neither the wrapper nor the
	// colliding body property should be registered as plain --all.
	assert.Equal(t, 0, counts["all"], "--all should not be present for create")

	// Colliding body properties get a body- prefix.
	assert.Equal(t, 1, counts["body-data"], "--body-data (prefixed body property)")
	assert.Equal(t, 1, counts["body-data-file"], "--body-data-file (prefixed body property)")
	assert.Equal(t, 1, counts["body-output"], "--body-output (prefixed body property)")
	assert.Equal(t, 1, counts["body-all"], "--body-all (prefixed body property)")

	// Non-colliding body property stays unprefixed.
	assert.Equal(t, 1, counts["name"], "--name (non-reserved body property)")
}

// TestNewApp_DpuExtensionServiceCreate_DoesNotPanic loads the real embedded
// OpenAPI spec and runs `nicocli dpu-extension-service create --help`. Prior
// to the reserved-flag fix this invocation panics with
// "create flag redefined: data" during urfave/cli flag-set construction.
func TestNewApp_DpuExtensionServiceCreate_DoesNotPanic(t *testing.T) {
	app, err := NewApp(openapi.Spec)
	require.NoError(t, err, "NewApp failed")

	require.NotPanics(t, func() {
		require.NoError(t, app.Run([]string{"nicocli", "dpu-extension-service", "create", "--help"}))
	})
}

// TestBuildActionCommand_UsageTextUsesBinaryName guards against regressing the
// dynamic usage string back to the literal "cli" prefix. Per-command --help
// output renders UsageText, so a wrong prefix shows up as
// "USAGE: cli site list" even though the binary is nicocli.
func TestBuildActionCommand_UsageTextUsesBinaryName(t *testing.T) {
	spec := &Spec{
		Paths: map[string]PathItem{
			"/v2/org/{org}/nico/site/{siteId}": {
				Get: &Operation{
					OperationID: "get-site",
					Tags:        []string{"Site"},
					Parameters: []Parameter{
						{Name: "siteId", In: "path"},
					},
				},
			},
		},
	}

	ro := resolvedOp{
		tag:    "Site",
		action: "get",
		method: "GET",
		path:   "/v2/org/{org}/nico/site/{siteId}",
		op:     spec.Paths["/v2/org/{org}/nico/site/{siteId}"].Get,
	}

	cmd := buildActionCommand(spec, ro, "")
	assert.Equal(t, "nicocli site get <siteId>", cmd.UsageText)
	assert.False(t, strings.HasPrefix(cmd.UsageText, "cli "),
		"UsageText must not start with the literal word 'cli '; got %q", cmd.UsageText)
}

// TestBuildCommands_AllUsageTextStartsWithBinaryName walks every dynamically
// built command from the embedded spec and asserts that the per-command
// UsageText begins with the actual binary name. This is the broadest form of
// the regression -- every leaf command renders UsageText in --help.
func TestBuildCommands_AllUsageTextStartsWithBinaryName(t *testing.T) {
	spec, err := ParseSpec(openapi.Spec)
	require.NoError(t, err, "ParseSpec failed")

	cmds := BuildCommands(spec)
	require.NotEmpty(t, cmds, "BuildCommands returned no commands")

	var visit func(path string, children []*cli.Command)
	visit = func(path string, children []*cli.Command) {
		for _, c := range children {
			full := path + " " + c.Name
			if c.UsageText != "" {
				assert.Truef(t, strings.HasPrefix(c.UsageText, "nicocli "),
					"command %q UsageText %q must start with %q",
					full, c.UsageText, "nicocli ")
			}
			if len(c.Subcommands) > 0 {
				visit(full, c.Subcommands)
			}
		}
	}
	visit("nicocli", cmds)
}

func TestDetectMisorderedFlags(t *testing.T) {
	usage := "nicocli machine update <machineId>"
	tests := []struct {
		name         string
		args         []string
		argParams    []string
		wantErr      bool
		wantContains []string
	}{
		{
			name:      "happy path - exactly the positional, no extras",
			args:      []string{"fm100htq"},
			argParams: []string{"machineId"},
			wantErr:   false,
		},
		{
			name:      "happy path - no positionals required and none given",
			args:      nil,
			argParams: nil,
			wantErr:   false,
		},
		{
			name:         "flag after positional - NVBug repro",
			args:         []string{"fm100htq", "--data", "{}"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"--data", "placed after a positional", "Move all flags before positionals", "[flags...] <machineId>"},
		},
		{
			name:         "flag=value form after positional",
			args:         []string{"fm100htq", "--data={}"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"--data", "placed after a positional"},
		},
		{
			name:         "short flag after positional",
			args:         []string{"fm100htq", "-o", "yaml"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"-o"},
		},
		{
			name:         "multiple flags after positional",
			args:         []string{"fm100htq", "--data", "{}", "--output", "yaml"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"--data", "--output"},
		},
		{
			name:         "per-field flag after positional",
			args:         []string{"fm100htq", "--instance-type-id", "uuid-here"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"--instance-type-id"},
		},
		{
			name:         "extra positional without leading dash",
			args:         []string{"fm100htq", "bonusId"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"unexpected positional argument", "bonusId"},
		},
		{
			name:         "extra positional plus misplaced flag",
			args:         []string{"fm100htq", "bonusId", "--data", "{}"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"--data", "bonusId", "unexpected positional"},
		},
		{
			name:         "lone dash is not treated as a flag",
			args:         []string{"fm100htq", "-"},
			argParams:    []string{"machineId"},
			wantErr:      true,
			wantContains: []string{"unexpected positional", "-"},
		},
		{
			name:      "multi-positional command with flags in correct order",
			args:      []string{"instanceTypeId-1", "machineAssociationId-1"},
			argParams: []string{"instanceTypeId", "machineAssociationId"},
			wantErr:   false,
		},
		{
			name:         "multi-positional command with flag inside a required positional slot",
			args:         []string{"instanceTypeId-1", "--data={}"},
			argParams:    []string{"instanceTypeId", "machineAssociationId"},
			wantErr:      true,
			wantContains: []string{"--data", "placed after a positional"},
		},
		{
			name:         "multi-positional command with trailing flag",
			args:         []string{"instanceTypeId-1", "machineAssociationId-1", "--data", "{}"},
			argParams:    []string{"instanceTypeId", "machineAssociationId"},
			wantErr:      true,
			wantContains: []string{"--data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectMisorderedFlagsInArgs(tt.args, tt.argParams, usage)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				for _, want := range tt.wantContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error missing %q:\n%s", want, err.Error())
					}
				}
			}
		})
	}
}

func TestIsActionModifier(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"status-history", true},
		{"stats", true},
		{"constraint", false},
		{"version", false},
		{"virtualization", false},
		{"machine-association", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isActionModifier(tt.input)
			if got != tt.want {
				t.Errorf("isActionModifier(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestBuildTagSubcommands_AliasCollisionExpandsAllNames documents the fix
// for the alias-collision determinism bug. When two operations under the
// same tag collapse to the same short action name (e.g.
// `get-current-infrastructure-provider` and
// `get-current-infrastructure-provider-stats` both -> `get`), the generated
// command tree must expose BOTH operations under their full OperationID and
// must NOT expose either under the colliding short name. Without this, the
// short alias non-deterministically points at one of the two operations
// depending on map iteration order, so the same binary exposes a different
// command surface depending on whether the config file was loaded.
func TestBuildTagSubcommands_AliasCollisionExpandsAllNames(t *testing.T) {
	infraProviderGet := &Operation{
		OperationID: "get-current-infrastructure-provider",
		Tags:        []string{"Infrastructure Provider"},
		Summary:     "Retrieve Infrastructure Provider for current Org",
	}
	infraProviderStats := &Operation{
		OperationID: "get-current-infrastructure-provider-stats",
		Tags:        []string{"Infrastructure Provider"},
		Summary:     "Retrieve Stats for current Infrastructure Provider",
	}
	ops := []resolvedOp{
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p1", op: infraProviderGet},
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p2", op: infraProviderStats},
	}

	cmds := buildTagSubcommands(&Spec{}, ops)

	names := make(map[string]int)
	for _, c := range cmds {
		names[c.Name]++
	}
	assert.Equal(t, 0, names["get"],
		"colliding short alias must be dropped entirely, not assigned to one operation non-deterministically")
	assert.Equal(t, 1, names["get-current-infrastructure-provider"])
	assert.Equal(t, 1, names["get-current-infrastructure-provider-stats"])
}

// TestBuildTagSubcommands_NonCollidingActionKeepsShortAlias is the negative
// counterpart to the collision test above: when there is exactly one
// operation per short action, the short alias is preserved.
func TestBuildTagSubcommands_NonCollidingActionKeepsShortAlias(t *testing.T) {
	op := &Operation{
		OperationID: "get-current-infrastructure-provider",
		Tags:        []string{"Infrastructure Provider"},
	}
	ops := []resolvedOp{
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p1", op: op},
	}

	cmds := buildTagSubcommands(&Spec{}, ops)

	require.Len(t, cmds, 1)
	assert.Equal(t, "get", cmds[0].Name,
		"a single-op tag must keep its short alias; collision-expansion must not over-fire")
}

// TestBuildTagSubcommands_AliasCollisionIsOrderIndependent simulates the two
// states the bug filer observed (config-loaded vs config-not-loaded) by
// running the resolver against both possible orderings of the colliding
// operations. The resulting command tree must be identical, so the binary's
// command surface no longer depends on Go map iteration order.
func TestBuildTagSubcommands_AliasCollisionIsOrderIndependent(t *testing.T) {
	infraProviderGet := &Operation{
		OperationID: "get-current-infrastructure-provider",
		Tags:        []string{"Infrastructure Provider"},
	}
	infraProviderStats := &Operation{
		OperationID: "get-current-infrastructure-provider-stats",
		Tags:        []string{"Infrastructure Provider"},
	}

	collectNames := func(ops []resolvedOp) []string {
		cmds := buildTagSubcommands(&Spec{}, ops)
		names := make([]string, 0, len(cmds))
		for _, c := range cmds {
			names = append(names, c.Name)
		}
		// Sort because primaryOps slice order is map-iteration-derived; we
		// only care that the *set* of names is identical across orderings.
		sortedNames := append([]string(nil), names...)
		sortStrings(sortedNames)
		return sortedNames
	}

	forward := collectNames([]resolvedOp{
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p1", op: infraProviderGet},
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p2", op: infraProviderStats},
	})
	reverse := collectNames([]resolvedOp{
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p2", op: infraProviderStats},
		{tag: "Infrastructure Provider", action: "get", method: "GET", path: "/p1", op: infraProviderGet},
	})
	assert.Equal(t, forward, reverse,
		"command surface must not depend on the order primaryOps is built in")
}

// TestNewApp_NoConfigDependentCommandSurface walks the embedded production
// spec and asserts that the two known alias-collision pairs (Infrastructure
// Provider and Tenant) expose the full operationId-derived names with no
// short `get` alias. This is the regression guard that fires if a future
// change re-introduces a "first one wins" alias resolver.
func TestNewApp_NoConfigDependentCommandSurface(t *testing.T) {
	app, err := NewApp(openapi.Spec)
	require.NoError(t, err, "NewApp failed")

	collidingPairs := map[string][]string{
		"infrastructure-provider": {
			"get-current-infrastructure-provider",
			"get-current-infrastructure-provider-stats",
		},
		"tenant": {
			"get-current-tenant",
			"get-current-tenant-stats",
		},
	}

	for tag, expected := range collidingPairs {
		t.Run(tag, func(t *testing.T) {
			var found *cli.Command
			for _, c := range app.Commands {
				if c.Name == tag {
					found = c
					break
				}
			}
			require.NotNilf(t, found, "tag %q should be present in the generated command tree", tag)

			subNames := make(map[string]bool)
			for _, sc := range found.Subcommands {
				subNames[sc.Name] = true
			}
			for _, want := range expected {
				assert.Truef(t, subNames[want],
					"tag %q must expose %q as a deterministic, full-name command", tag, want)
			}
			assert.Falsef(t, subNames["get"],
				"tag %q must NOT expose `get` as a short alias when there are %d colliding operations",
				tag, len(expected))
		})
	}
}

// sortStrings is a tiny stable sort used by the order-independence test so it
// stays self-contained and does not pull in sort.Strings (which is already
// used elsewhere; this just keeps the test readable).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
