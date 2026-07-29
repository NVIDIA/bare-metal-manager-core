// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ptyAuthToken              = "pty-auth-token-that-must-not-be-printed"
	ptyBMCPassword            = "pty-bmc-password-that-must-not-be-printed"
	ptyDelegationClientSecret = "pty-oauth-secret-that-must-not-be-printed"
	nonInteractiveBMCPassword = "noninteractive-password-that-must-not-be-printed"
)

type cliRegressionRequest struct {
	Method        string
	Path          string
	Query         string
	Authorization string
	Accept        string
	ContentType   string
	Body          string
}

type cliRegressionRecorder struct {
	mu       sync.Mutex
	requests []cliRegressionRequest
}

func (r *cliRegressionRecorder) append(request cliRegressionRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, request)
}

func (r *cliRegressionRecorder) snapshot() []cliRegressionRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]cliRegressionRequest(nil), r.requests...)
}

func (r *cliRegressionRecorder) matching(method, path string) []cliRegressionRequest {
	var matches []cliRegressionRequest
	for _, request := range r.snapshot() {
		if request.Method == method && request.Path == path {
			matches = append(matches, request)
		}
	}
	return matches
}

func TestCLIRegression_RealTerminalAndNonInteractive(t *testing.T) {
	binaryPath := buildRegressionCLI(t)

	t.Run("interactive PTY exercises navigation scopes generated forms and secrets", func(t *testing.T) {
		recorder := &cliRegressionRecorder{}
		server := httptest.NewServer(newInteractiveRegressionHandler(recorder))
		defer server.Close()

		configPath := writeRegressionConfig(t, server.URL)
		command := exec.Command(binaryPath, "--config", configPath, "tui")
		command.Env = regressionEnvironment(map[string]string{
			"NICO_TOKEN":     ptyAuthToken,
			"TERM":           "xterm-256color",
			"COLORTERM":      "truecolor",
			"CLICOLOR_FORCE": "1",
		})

		terminal := startRegressionPTY(t, command)
		defer terminal.close()

		terminal.waitFor(t, "NICo Interactive Mode")
		terminal.waitFor(t, "Type a command or")

		// Command discovery, autocomplete, help, unknown-command recovery, and
		// Ctrl+C line clearing all go through the real raw-mode REPL.
		terminal.send(t, "hel\t\r")
		terminal.waitFor(t, "KEYBINDINGS")
		helpTranscript := terminal.transcript()
		assert.Regexp(t, `machine power\s+Machine power control`, helpTranscript)
		assert.Regexp(
			t,
			`machine power-control-machine machine-power-control-machine\s+Machine power control`,
			helpTranscript,
		)
		terminal.send(t, "definitely-not-a-command\r")
		terminal.waitFor(t, "unknown command: definitely-not-a-command")
		terminal.send(t, "discard-this-line")
		terminal.sendBytes(t, []byte{KeyCtrlC})
		terminal.send(t, "scope\r")
		terminal.waitFor(t, "No scope set.")

		// A lone Escape must cancel a real selector without waiting forever.
		terminal.send(t, "scope site\r")
		terminal.waitFor(t, "Site:")
		terminal.sendBytes(t, []byte{KeyEscape})
		terminal.waitFor(t, "selection cancelled")

		// Direct name resolution, dependent VPC scope, scope display, and clear.
		terminal.send(t, "scope site site-one\r")
		terminal.waitFor(t, "Scope set: site =")
		terminal.send(t, "scope vpc vpc-one\r")
		terminal.waitFor(t, "Scope set: vpc =")
		terminal.send(t, "scope\r")
		terminal.waitFor(t, "vpc-one")
		terminal.send(t, "scope clear\r")
		terminal.waitFor(t, "Scope cleared.")
		terminal.send(t, "scope\r")
		terminal.waitFor(t, "No scope set.")

		// Both the concise alias and exact generated path remain discoverable,
		// complete machine names, and dispatch the same REST operation.
		for _, commandName := range []string{
			"machine power",
			"machine power-control-machine machine-power-control-machine",
		} {
			terminal.send(t, commandName+" --action ForceRestart host")
			terminal.waitFor(t, commandName+" --action ForceRestart host-one")
			terminal.send(t, "\t\r")
			terminal.waitFor(t, "Run "+commandName+" (PATCH)?")
			terminal.send(t, "y\r")
			terminal.waitFor(t, `"status": "accepted"`)
		}

		// Flags preceding a generated path argument must not disable
		// resource-name completion, and the structured API error must render.
		terminal.send(t, "machine status-history --page-size 10 host")
		terminal.waitFor(t, "machine status-history --page-size 10 host-one")
		terminal.send(t, "\t\r")
		terminal.waitFor(t, "API error 422: history unavailable")

		// Resolve both parent and nested path values by their selectable names.
		terminal.send(t, "dpu-extension-service version get\r")
		terminal.waitFor(t, "Dpu extension service id:")
		terminal.send(t, "telemetry\r")
		terminal.waitFor(t, "Version:")
		terminal.send(t, "v1\r")
		terminal.waitFor(t, `"version": "v1"`)

		// Keep a pre-existing specialized list handler on the same real
		// terminal path as generated commands.
		terminal.send(t, "site list\r")
		terminal.waitFor(t, "site-two")

		// Raw JSON remains an escape hatch and mutations still require an
		// explicit confirmation. The cancelled attempt must not reach the API.
		terminal.send(t, `vpc-peering create --data '{"siteId":"site-1","vpc1Id":"vpc-1","vpc2Id":"vpc-2"}'`+"\r")
		terminal.waitFor(t, "Run vpc-peering create (POST)?")
		terminal.send(t, "n\r")
		terminal.waitFor(t, "nico:acme")

		// Guided request bodies preload site/VPC names, resolve two body IDs in
		// order, and execute only after confirmation.
		terminal.send(t, "vpc-peering create\r")
		terminal.waitFor(t, "Request body input")
		terminal.send(t, "\r")
		terminal.waitFor(t, "Site id:")
		terminal.send(t, "site-one\r")
		terminal.waitFor(t, "Vpc1id:")
		terminal.send(t, "vpc-one\r")
		terminal.waitFor(t, "Vpc2id:")
		terminal.send(t, "vpc-two\r")
		terminal.waitFor(t, "Run vpc-peering create (POST)?")
		terminal.send(t, "y\r")
		terminal.waitFor(t, `"id": "peering-1"`)

		// Generated enum and secret fields use the guided form. Optional
		// free-form fields can be skipped, and terminal password input is not
		// echoed.
		terminal.send(t, "bmc-credential create\r")
		terminal.waitFor(t, "Request body input")
		terminal.send(t, "\r")
		terminal.waitFor(t, "Kind")
		terminal.send(t, "SiteWideRoot\r")
		terminal.waitFor(t, "Mac address (optional)")
		terminal.send(t, "\r")
		terminal.waitFor(t, "Password")
		terminal.waitForEchoDisabled(t)
		terminal.send(t, ptyBMCPassword+"\r")
		terminal.waitFor(t, "Username (optional)")
		terminal.send(t, "\r")
		terminal.waitFor(t, "Run bmc-credential create (PUT)?")
		terminal.send(t, "y\r")
		terminal.waitFor(t, `"id": "credential-1"`)

		// The pre-existing specialized tenant-identity form is also reachable
		// through a generated alias; its write-only client secret must use the
		// same no-echo terminal behavior.
		terminal.send(t, "tenant-identity token-delegation update\r")
		terminal.waitFor(t, "tokenEndpoint")
		terminal.send(t, "https://exchange.example.test/token\r")
		terminal.waitFor(t, "subjectTokenAudience")
		terminal.send(t, "spiffe://example.test/workload\r")
		terminal.waitFor(t, "clientSecretBasic")
		terminal.send(t, "y\r")
		terminal.waitFor(t, "clientSecretBasic.clientId")
		terminal.send(t, "nicocli-regression\r")
		terminal.waitFor(t, "clientSecretBasic.clientSecret")
		terminal.waitForEchoDisabled(t)
		terminal.send(t, ptyDelegationClientSecret+"\r")
		terminal.waitFor(t, "Token delegation saved")

		terminal.send(t, "env --mask\r")
		terminal.waitFor(t, "REDACTED")
		terminal.send(t, "exit\r")
		terminal.waitFor(t, "Goodbye.")
		terminal.waitForExit(t)

		transcript := terminal.transcript()
		assert.NotContains(t, transcript, ptyAuthToken)
		assert.NotContains(t, transcript, ptyBMCPassword)
		assert.NotContains(t, transcript, ptyDelegationClientSecret)

		requests := recorder.snapshot()
		require.NotEmpty(t, requests)
		for _, request := range requests {
			assert.Equal(t, "Bearer "+ptyAuthToken, request.Authorization, request.Path)
			assert.Equal(t, "application/json", request.Accept, request.Path)
			if request.Body != "" {
				assert.Equal(t, "application/json", request.ContentType, request.Path)
			}
		}

		historyRequests := recorder.matching(
			http.MethodGet,
			"/v2/org/acme/nico/machine/machine-1/status-history",
		)
		require.Len(t, historyRequests, 1)
		assert.Contains(t, historyRequests[0].Query, "pageSize=10")

		powerRequests := recorder.matching(
			http.MethodPatch,
			"/v2/org/acme/nico/machine/machine-1/power",
		)
		require.Len(t, powerRequests, 2)
		for _, request := range powerRequests {
			assert.JSONEq(t, `{"action":"ForceRestart"}`, request.Body)
		}

		versionRequests := recorder.matching(
			http.MethodGet,
			"/v2/org/acme/nico/dpu-extension-service/service-1/version/v1",
		)
		require.Len(t, versionRequests, 1)

		peeringRequests := recorder.matching(
			http.MethodPost,
			"/v2/org/acme/nico/vpc-peering",
		)
		require.Len(t, peeringRequests, 1, "cancelled mutation must not reach the API")
		assert.JSONEq(
			t,
			`{"siteId":"site-1","vpc1Id":"vpc-1","vpc2Id":"vpc-2"}`,
			peeringRequests[0].Body,
		)

		bmcRequests := recorder.matching(
			http.MethodPut,
			"/v2/org/acme/nico/credential/bmc",
		)
		require.Len(t, bmcRequests, 1)
		assert.JSONEq(
			t,
			fmt.Sprintf(
				`{"siteId":"site-1","kind":"SiteWideRoot","password":%q}`,
				ptyBMCPassword,
			),
			bmcRequests[0].Body,
		)

		delegationRequests := recorder.matching(
			http.MethodPut,
			"/v2/org/acme/nico/site/site-1/tenant-identity/token-delegation",
		)
		require.Len(t, delegationRequests, 1)
		assert.Contains(t, delegationRequests[0].Body, ptyDelegationClientSecret)

		var vpcQueries []string
		for _, request := range recorder.matching(http.MethodGet, "/v2/org/acme/nico/vpc") {
			vpcQueries = append(vpcQueries, request.Query)
		}
		require.NotEmpty(t, vpcQueries)
		for _, query := range vpcQueries {
			assert.Contains(t, query, "siteId=site-1")
		}
	})

	t.Run("non-interactive generated command keeps shared debug output redacted", func(t *testing.T) {
		recorder := &cliRegressionRecorder{}
		server := httptest.NewServer(newInteractiveRegressionHandler(recorder))
		defer server.Close()

		configPath := writeRegressionConfig(t, server.URL)
		body := fmt.Sprintf(
			`{"siteId":"site-1","kind":"SiteWideRoot","password":%q}`,
			nonInteractiveBMCPassword,
		)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(
			ctx,
			binaryPath,
			"--config", configPath,
			"--debug",
			"bmc-credential", "create",
			"--data", body,
		)
		command.Env = regressionEnvironment(map[string]string{
			"NICO_TOKEN": ptyAuthToken,
		})
		output, err := command.CombinedOutput()
		require.NoError(t, err, "non-interactive command output:\n%s", sanitizeRegressionOutput(string(output)))

		text := string(output)
		assert.NotContains(t, text, ptyAuthToken)
		assert.NotContains(t, text, nonInteractiveBMCPassword)
		assert.Contains(t, text, "NICO_TOKEN")
		assert.Contains(t, text, "REDACTED")
		assert.Contains(t, text, "Request body:")
		assert.Contains(t, text, "<redacted>")
		assert.Contains(t, text, `"id": "credential-noninteractive"`)

		requests := recorder.matching(
			http.MethodPut,
			"/v2/org/acme/nico/credential/bmc",
		)
		require.Len(t, requests, 1)
		assert.Contains(t, requests[0].Body, nonInteractiveBMCPassword)
		assert.Equal(t, "Bearer "+ptyAuthToken, requests[0].Authorization)
	})
}

func buildRegressionCLI(t *testing.T) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "nicocli")
	command := exec.Command("go", "build", "-o", binaryPath, "../cmd/cli")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "building nicocli:\n%s", output)
	return binaryPath
}

func writeRegressionConfig(t *testing.T, baseURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := fmt.Sprintf(
		"api:\n  base: %s\n  org: acme\n  name: nico\nauth:\n  token: %s\n",
		baseURL,
		ptyAuthToken,
	)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func regressionEnvironment(overrides map[string]string) []string {
	values := make(map[string]string, len(overrides))
	for key, value := range overrides {
		values[key] = value
	}
	var environment []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "NICO_") {
			continue
		}
		if _, replaced := values[key]; replaced {
			continue
		}
		environment = append(environment, entry)
	}
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func newInteractiveRegressionHandler(recorder *cliRegressionRecorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		recorder.append(cliRegressionRequest{
			Method:        request.Method,
			Path:          request.URL.Path,
			Query:         request.URL.RawQuery,
			Authorization: request.Header.Get("Authorization"),
			Accept:        request.Header.Get("Accept"),
			ContentType:   request.Header.Get("Content-Type"),
			Body:          string(body),
		})
		w.Header().Set("Content-Type", "application/json")

		switch {
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/site":
			_, _ = io.WriteString(w, `[
				{"id":"site-1","name":"site-one","status":"Ready"},
				{"id":"site-2","name":"site-two","status":"Ready"}
			]`)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/vpc":
			_, _ = io.WriteString(w, `[
				{"id":"vpc-1","name":"vpc-one","siteId":"site-1","status":"Ready"},
				{"id":"vpc-2","name":"vpc-two","siteId":"site-1","status":"Ready"}
			]`)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/machine":
			_, _ = io.WriteString(w, `[
				{
					"id":"machine-1",
					"labels":{"hostname":"host-one"},
					"siteId":"site-1",
					"status":"Ready"
				}
			]`)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/machine/machine-1/status-history":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(
				w,
				`{"message":"history unavailable","data":{"field":"machineId"}}`,
			)
		case request.Method == http.MethodPatch &&
			request.URL.Path == "/v2/org/acme/nico/machine/machine-1/power":
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"status":"accepted"}`)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/dpu-extension-service":
			_, _ = io.WriteString(w, `[
				{"id":"service-1","name":"telemetry","siteId":"site-1"},
				{"id":"service-2","name":"storage","siteId":"site-1"}
			]`)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/dpu-extension-service/service-1":
			_, _ = io.WriteString(
				w,
				`{"id":"service-1","name":"telemetry","version":"v2","activeVersions":["v1","v2"]}`,
			)
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v2/org/acme/nico/dpu-extension-service/service-1/version/v1":
			_, _ = io.WriteString(
				w,
				`{"id":"service-1","name":"telemetry","version":"v1"}`,
			)
		case request.Method == http.MethodPost &&
			request.URL.Path == "/v2/org/acme/nico/vpc-peering":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"peering-1","status":"Ready"}`)
		case request.Method == http.MethodPut &&
			request.URL.Path == "/v2/org/acme/nico/credential/bmc":
			w.WriteHeader(http.StatusAccepted)
			id := "credential-1"
			if bytes.Contains(body, []byte(nonInteractiveBMCPassword)) {
				id = "credential-noninteractive"
			}
			_, _ = fmt.Fprintf(w, `{"id":%q,"siteId":"site-1","kind":"SiteWideRoot"}`, id)
		case request.Method == http.MethodPut &&
			request.URL.Path == "/v2/org/acme/nico/site/site-1/tenant-identity/token-delegation":
			_, _ = io.WriteString(
				w,
				`{"tokenEndpoint":"https://exchange.example.test/token","subjectTokenAudience":"spiffe://example.test/workload"}`,
			)
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf(
					"unexpected regression request: %s %s",
					request.Method,
					request.URL.RequestURI(),
				),
			})
		}
	})
}

type regressionPTY struct {
	command *exec.Cmd
	file    *os.File

	mu      sync.Mutex
	output  bytes.Buffer
	cursor  int
	readErr error
	notify  chan struct{}

	waitOnce sync.Once
	waitErr  error
}

func startRegressionPTY(t *testing.T, command *exec.Cmd) *regressionPTY {
	t.Helper()
	file, err := pty.Start(command)
	require.NoError(t, err)
	require.NoError(t, pty.Setsize(file, &pty.Winsize{Rows: 60, Cols: 180}))

	session := &regressionPTY{
		command: command,
		file:    file,
		notify:  make(chan struct{}, 1),
	}
	go session.read()
	return session
}

func (s *regressionPTY) read() {
	buffer := make([]byte, 4096)
	for {
		n, err := s.file.Read(buffer)
		s.mu.Lock()
		if n > 0 {
			_, _ = s.output.Write(buffer[:n])
		}
		if err != nil {
			s.readErr = err
		}
		s.mu.Unlock()
		select {
		case s.notify <- struct{}{}:
		default:
		}
		if err != nil {
			return
		}
	}
}

func (s *regressionPTY) send(t *testing.T, value string) {
	t.Helper()
	s.sendBytes(t, []byte(value))
}

func (s *regressionPTY) sendBytes(t *testing.T, value []byte) {
	t.Helper()
	_, err := s.file.Write(value)
	require.NoError(t, err)
}

func (s *regressionPTY) waitFor(t *testing.T, expected string) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	for {
		s.mu.Lock()
		output := s.output.String()
		if index := strings.Index(output[s.cursor:], expected); index >= 0 {
			s.cursor += index + len(expected)
			s.mu.Unlock()
			return
		}
		readErr := s.readErr
		s.mu.Unlock()

		if readErr != nil {
			t.Fatalf(
				"terminal ended before %q appeared: %v\ntranscript:\n%s",
				expected,
				readErr,
				sanitizeRegressionOutput(output),
			)
		}
		select {
		case <-s.notify:
		case <-timer.C:
			t.Fatalf(
				"timed out waiting for %q\ntranscript:\n%s",
				expected,
				sanitizeRegressionOutput(output),
			)
		}
	}
}

func (s *regressionPTY) waitForEchoDisabled(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		enabled, err := regressionPTYEchoEnabled(s.file)
		require.NoError(t, err)
		if !enabled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"terminal echo stayed enabled at a secret prompt\ntranscript:\n%s",
				sanitizeRegressionOutput(s.transcript()),
			)
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *regressionPTY) transcript() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.output.String()
}

func (s *regressionPTY) waitForExit(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.wait()
		close(done)
	}()
	select {
	case <-done:
		require.NoError(t, s.waitErr)
	case <-time.After(10 * time.Second):
		t.Fatalf("nicocli did not exit\ntranscript:\n%s", sanitizeRegressionOutput(s.transcript()))
	}
}

func (s *regressionPTY) wait() {
	s.waitOnce.Do(func() {
		s.waitErr = s.command.Wait()
	})
}

func (s *regressionPTY) close() {
	_ = s.file.Close()
	if s.command.ProcessState == nil {
		_ = s.command.Process.Kill()
	}
	s.wait()
}

func sanitizeRegressionOutput(output string) string {
	for _, secret := range []string{
		ptyAuthToken,
		ptyBMCPassword,
		ptyDelegationClientSecret,
		nonInteractiveBMCPassword,
	} {
		output = strings.ReplaceAll(output, secret, "<test-secret-redacted>")
	}
	return output
}
