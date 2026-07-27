// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	appcli "github.com/NVIDIA/infra-controller/rest-api/cli/pkg"
	"github.com/NVIDIA/infra-controller/rest-api/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfavecli "github.com/urfave/cli/v2"
)

func TestAllCommands_CoversGeneratedCLISurface(t *testing.T) {
	spec, err := appcli.ParseSpec(openapi.Spec)
	require.NoError(t, err)

	generatedNames := flattenGeneratedCommandNames(appcli.BuildCommands(spec))
	generated := make(map[string]struct{}, len(generatedNames))
	for _, name := range generatedNames {
		generated[name] = struct{}{}
	}

	tuiCommands := make(map[string]struct{}, len(AllCommands()))
	for _, command := range AllCommands() {
		tuiCommands[command.Name] = struct{}{}
	}

	for source, target := range generatedCommandAliases {
		_, sourceExists := generated[source]
		assert.Truef(t, sourceExists, "alias source %q is not a generated CLI command", source)
		_, targetExists := tuiCommands[target]
		assert.Truef(t, targetExists, "alias target %q is not a TUI command", target)
		_, alsoExcluded := generatedCommandExclusions[source]
		assert.Falsef(t, alsoExcluded, "generated command %q is both aliased and excluded", source)
	}
	for name, reason := range generatedCommandExclusions {
		_, exists := generated[name]
		assert.Truef(t, exists, "excluded command %q is not a generated CLI command", name)
		assert.NotEmptyf(t, strings.TrimSpace(reason), "excluded command %q needs a reviewed reason", name)
	}

	var missing []string
	for _, name := range generatedNames {
		if _, exists := tuiCommands[name]; exists {
			continue
		}
		if target, aliased := generatedCommandAliases[name]; aliased {
			if _, exists := tuiCommands[target]; exists {
				continue
			}
		}
		if _, excluded := generatedCommandExclusions[name]; excluded {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	assert.Empty(t, missing, "generated CLI commands missing from the TUI")
}

func TestAllCommands_RegistersRepresentativeFormerGaps(t *testing.T) {
	commands := commandNames(AllCommands())
	for _, name := range []string{
		"allocation constraint update",
		"bmc-credential create",
		"dpu-extension-service version get",
		"expected-machine batch-create",
		"health-report list",
		"instance-type machine-association create",
		"ip-block derived list",
		"ipxe-template list",
		"machine capabilities list",
		"rack bringup-racks bringup-racks",
		"rule list-rules list-rules",
		"site-explorer create",
		"uefi-credential create",
		"vpc-peering list",
	} {
		assert.Containsf(t, commands, name, "expected generated fallback %q", name)
	}
}

func TestAppendGeneratedCommandInfos_RegistersFutureOperation(t *testing.T) {
	spec, err := appcli.ParseSpec([]byte(`
info:
  title: test
  version: test
paths:
  /v2/org/{org}/nico/trusted-machine:
    get:
      tags: [Trusted Machine]
      summary: List trusted machines
      operationId: get-all-trusted-machine
`))
	require.NoError(t, err)

	commands := appendGeneratedCommandInfos(
		[]Command{{Name: "help", Run: cmdHelp}},
		appcli.GeneratedCommandInfos(spec),
	)

	require.Len(t, commands, 2)
	assert.Equal(t, "trusted-machine list", commands[1].Name)
	assert.NotNil(t, commands[1].Run)
}

func TestAppendGeneratedCommandInfos_CoversPendingMeasuredBootOperations(t *testing.T) {
	spec, err := appcli.ParseSpec([]byte(`
info:
  title: measured boot parity
  version: test
paths:
  /v2/org/{org}/nico/measured-boot/trusted-machine:
    post:
      tags: [Measured Boot Trusted Machine]
      operationId: create-measurement-trusted-machine
    get:
      tags: [Measured Boot Trusted Machine]
      operationId: get-all-measurement-trusted-machine
  /v2/org/{org}/nico/measured-boot/trusted-machine/{id}:
    delete:
      tags: [Measured Boot Trusted Machine]
      operationId: delete-measurement-trusted-machine
  /v2/org/{org}/nico/measured-boot/trusted-profile:
    post:
      tags: [Measured Boot Trusted Profile]
      operationId: create-measurement-trusted-profile
    get:
      tags: [Measured Boot Trusted Profile]
      operationId: get-all-measurement-trusted-profile
  /v2/org/{org}/nico/measured-boot/trusted-profile/{id}:
    delete:
      tags: [Measured Boot Trusted Profile]
      operationId: delete-measurement-trusted-profile
`))
	require.NoError(t, err)

	commands := appendGeneratedCommandInfos(nil, appcli.GeneratedCommandInfos(spec))
	names := commandNames(commands)
	for _, name := range []string{
		"measured-boot-trusted-machine create",
		"measured-boot-trusted-machine list",
		"measured-boot-trusted-machine delete",
		"measured-boot-trusted-profile create",
		"measured-boot-trusted-profile list",
		"measured-boot-trusted-profile delete",
	} {
		assert.Contains(t, names, name)
	}
}

func TestGeneratedCommand_ReadOnlyUsesSessionClientScopeAndFetchesAll(t *testing.T) {
	type request struct {
		path          string
		query         string
		authorization string
	}
	requests := make(chan request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- request{
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"type":"GPU","name":"H100"}]`)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "session-token", nil, false)
	client.APIName = "custom-api"
	session := NewSession(client, "acme", "/tmp/config with spaces.yaml")
	session.Scope.SiteID = "site-1"

	command := requireTUICommand(t, "machine capabilities list")
	var runErr error
	output := captureStdout(func() {
		runErr = command.Run(session, nil)
	})
	require.NoError(t, runErr)

	got := <-requests
	assert.Equal(t, "/v2/org/acme/custom-api/machine-capability", got.path)
	assert.Contains(t, got.query, "siteId=site-1")
	assert.Contains(t, got.query, "pageNumber=1")
	assert.Contains(t, got.query, "pageSize=100")
	assert.Equal(t, "Bearer session-token", got.authorization)
	assert.Contains(t, output, "nicocli")
	assert.Contains(t, output, "--site-id site-1")
	assert.Contains(t, output, "--all")
	assert.Contains(t, output, `"H100"`)
}

func TestGeneratedCommand_PromptsForRequiredQuery(t *testing.T) {
	requestQuery := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestQuery <- r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[]`)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "token", nil, false)
	session := &Session{Client: client, Cache: NewCache()}
	command := requireTUICommand(t, "machine capabilities list")

	_, err := withStdin(t, "site-from-prompt\n", func() (string, error) {
		return "", command.Run(session, nil)
	})
	require.NoError(t, err)
	assert.Contains(t, <-requestQuery, "siteId=site-from-prompt")
}

func TestGeneratedCommand_MutationConfirmsRedactsAndInvalidatesCache(t *testing.T) {
	type request struct {
		method        string
		path          string
		body          string
		authorization string
	}
	requests := make(chan request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- request{
			method:        r.Method,
			path:          r.URL.Path,
			body:          string(body),
			authorization: r.Header.Get("Authorization"),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"siteId":"site-1","kind":"Host"}`)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "session-token", nil, false)
	cache := NewCache()
	cache.Set("site", []NamedItem{{Name: "Site One", ID: "site-1"}})
	session := &Session{
		Client:     client,
		ConfigPath: "/tmp/config.yaml",
		Cache:      cache,
		Scope:      Scope{SiteID: "site-1"},
	}
	command := requireTUICommand(t, "uefi-credential create")
	body := `{"kind":"Host","password":"super-secret"}`

	output, err := withStdin(t, "y\n", func() (string, error) {
		var runErr error
		out := captureStdout(func() {
			runErr = command.Run(session, []string{"--data", body})
		})
		return out, runErr
	})
	require.NoError(t, err)

	got := <-requests
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/v2/org/acme/nico/credential/uefi", got.path)
	assert.JSONEq(t, `{"siteId":"site-1","kind":"Host","password":"super-secret"}`, got.body)
	assert.Equal(t, "Bearer session-token", got.authorization)
	assert.Contains(t, output, "Run uefi-credential create (POST)?")
	assert.Contains(t, output, "nicocli")
	assert.Contains(t, output, "--data <redacted>")
	assert.NotContains(t, output, "super-secret")
	assert.Nil(t, cache.Get("site"), "successful mutations must invalidate cached resources")
}

func TestGeneratedCommand_CancelledMutationDoesNotCallAPI(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "token", nil, false)
	cache := NewCache()
	cache.Set("machine", []NamedItem{{Name: "host-one", ID: "machine-1"}})
	session := &Session{Client: client, Cache: cache}
	command := requireTUICommand(t, "machine delete")

	output, err := withStdin(t, "n\n", func() (string, error) {
		var runErr error
		out := captureStdout(func() {
			runErr = command.Run(session, []string{"machine-1"})
		})
		return out, runErr
	})
	require.NoError(t, err)
	assert.Zero(t, calls.Load())
	assert.NotNil(t, cache.Get("machine"), "cancelled mutations must preserve the cache")
	assert.NotContains(t, output, "INFO:")
}

func TestGeneratedCommand_HelpLikeValuesDoNotBypassConfirmation(t *testing.T) {
	for name, args := range map[string][]string{
		"false help flag": {"--help=false", "--data", `{"kind":"Host"}`},
		"help-like value": {"--data", "--help"},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()

			session := &Session{
				Client: appcli.NewClient(server.URL, "acme", "token", nil, false),
				Cache:  NewCache(),
			}
			command := requireTUICommand(t, "uefi-credential create")

			output, err := withStdin(t, "n\n", func() (string, error) {
				var runErr error
				out := captureStdout(func() {
					runErr = command.Run(session, args)
				})
				return out, runErr
			})
			require.NoError(t, err)
			assert.Zero(t, calls.Load())
			assert.Contains(t, output, "Run uefi-credential create (POST)?")
			assert.NotContains(t, output, "USAGE:")
		})
	}
}

func TestGeneratedCommand_SensitiveNestedAndArrayBodiesRedactHistory(t *testing.T) {
	for _, name := range []string{
		"dpu-extension-service create",
		"expected-machine batch-create",
	} {
		info := requireGeneratedInfo(t, name)
		assert.True(t, generatedCommandHasSensitiveBody(info), name)

		command := requireTUICommand(t, name)
		assert.True(t, command.Sensitive, name)
		commandMap := map[string]Command{name: command}
		got := commandHistoryLine(name+` --data '{"password":"secret"}'`, commandMap, []Command{command})
		assert.Equal(t, name+" <redacted>", got)
	}
}

func TestGeneratedCommand_DataFileArrayInheritsSiteScope(t *testing.T) {
	requestBody := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody <- string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `[]`)
	}))
	defer server.Close()

	dataFile := t.TempDir() + "/expected-machines.json"
	require.NoError(t, os.WriteFile(
		dataFile,
		[]byte(`[{"bmcMacAddress":"00:11:22:33:44:55","defaultBmcPassword":"file-secret"}]`),
		0o600,
	))
	session := &Session{
		Client: appcli.NewClient(server.URL, "acme", "token", nil, false),
		Cache:  NewCache(),
		Scope:  Scope{SiteID: "site-from-scope"},
	}
	command := requireTUICommand(t, "expected-machine batch-create")

	output, err := withStdin(t, "y\n", func() (string, error) {
		var runErr error
		out := captureStdout(func() {
			runErr = command.Run(session, []string{"--data-file", dataFile})
		})
		return out, runErr
	})
	require.NoError(t, err)
	assert.JSONEq(t,
		`[{"siteId":"site-from-scope","bmcMacAddress":"00:11:22:33:44:55","defaultBmcPassword":"file-secret"}]`,
		<-requestBody,
	)
	assert.Contains(t, output, "--data <redacted>")
	assert.NotContains(t, output, "file-secret")
}

func TestGeneratedCommand_UnpaginatedListDoesNotFetchAll(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) > 1 {
			http.Error(w, "unexpected repeated request", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		items := "[" + strings.TrimSuffix(strings.Repeat(`{"machineId":"machine-1"},`, 100), ",") + "]"
		_, _ = io.WriteString(w, items)
	}))
	defer server.Close()

	session := &Session{
		Client: appcli.NewClient(server.URL, "acme", "token", nil, false),
		Cache:  NewCache(),
		Scope:  Scope{SiteID: "site-1"},
	}
	command := requireTUICommand(t, "health-report list")
	var runErr error
	output := captureStdout(func() {
		runErr = command.Run(session, []string{"machine-1"})
	})
	require.NoError(t, runErr)
	assert.Equal(t, int32(1), calls.Load())
	assert.NotContains(t, output, "--all")
}

func TestGeneratedCommand_ResolvesNamesAndReturnsAPIErrors(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"history unavailable"}`)
	}))
	defer server.Close()

	client := appcli.NewClient(server.URL, "acme", "token", nil, false)
	cache := NewCache()
	cache.Set("machine", []NamedItem{{Name: "host-one", ID: "machine-1"}})
	resolver := NewResolver(cache)
	resolver.RegisterFetcher("machine", func(context.Context) ([]NamedItem, error) {
		return nil, assert.AnError
	})
	session := &Session{Client: client, Cache: cache, Resolver: resolver}
	command := requireTUICommand(t, "machine status-history")

	err := command.Run(session, []string{"host-one"})
	require.Error(t, err)
	assert.Equal(t, "/v2/org/acme/nico/machine/machine-1/status-history", <-requestPath)
	assert.Contains(t, err.Error(), "history unavailable")
}

func TestSplitCommandArguments_PreservesQuotedJSON(t *testing.T) {
	got, err := splitCommandArguments(`--data '{"name": "two words"}' machine-1`)
	require.NoError(t, err)
	assert.Equal(t, []string{"--data", `{"name": "two words"}`, "machine-1"}, got)
}

func TestSplitCommandArguments_RejectsUnterminatedQuote(t *testing.T) {
	_, err := splitCommandArguments(`--data '{"name":"broken"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

func TestValidateGeneratedBodyArguments_RejectsCompetingInputs(t *testing.T) {
	info := appcli.GeneratedCommandInfo{
		Flags: []appcli.GeneratedCommandFlag{
			{Name: "data", TakesValue: true},
			{Name: "password", TakesValue: true},
		},
		BodyFields: []appcli.GeneratedCommandBodyField{{
			JSONName: "password",
			FlagName: "password",
		}},
	}
	err := validateGeneratedBodyArguments(info, []string{
		"--data", `{"password":"secret"}`,
		"--password", "other-secret",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--data cannot be combined")
}

func TestMatchCommandLine_UsesLongestBoundaryMatch(t *testing.T) {
	commands := []Command{
		{Name: "rule list", Description: "short"},
		{Name: "rule list-rules list-rules", Description: "long"},
	}
	commandMap := map[string]Command{}
	for _, command := range commands {
		commandMap[command.Name] = command
	}

	command, rest, ok := matchCommandLine("rule list-rules list-rules --all", commandMap, commands)
	require.True(t, ok)
	assert.Equal(t, "rule list-rules list-rules", command.Name)
	assert.Equal(t, "--all", rest)
}

func flattenGeneratedCommandNames(commands []*urfavecli.Command) []string {
	var names []string
	var walk func([]string, []*urfavecli.Command)
	walk = func(prefix []string, current []*urfavecli.Command) {
		for _, command := range current {
			path := append(append([]string(nil), prefix...), command.Name)
			if len(command.Subcommands) == 0 {
				names = append(names, strings.Join(path, " "))
				continue
			}
			walk(path, command.Subcommands)
		}
	}
	walk(nil, commands)
	sort.Strings(names)
	return names
}

func commandNames(commands []Command) map[string]struct{} {
	names := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		names[command.Name] = struct{}{}
	}
	return names
}

func requireTUICommand(t *testing.T, name string) Command {
	t.Helper()
	for _, command := range AllCommands() {
		if command.Name == name {
			return command
		}
	}
	t.Fatalf("TUI command %q not found", name)
	return Command{}
}

func requireGeneratedInfo(t *testing.T, name string) appcli.GeneratedCommandInfo {
	t.Helper()
	for _, info := range embeddedGeneratedCommandInfos {
		if info.Name == name {
			return info
		}
	}
	t.Fatalf("generated command info %q not found", name)
	return appcli.GeneratedCommandInfo{}
}
