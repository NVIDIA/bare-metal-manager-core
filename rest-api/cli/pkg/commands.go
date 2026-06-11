// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

type resolvedOp struct {
	tag        string
	action     string
	method     string
	path       string
	op         *Operation
	pathParams []Parameter
}

// bodyField tracks a request body property for type-aware flag reading.
type bodyField struct {
	jsonName string
	flagName string
	schema   *Schema
}

// reservedBodyFlagNames are flag names owned by the CLI wrapper. Body
// properties whose kebab-cased name matches one of these get a "body-"
// prefix during flag registration (e.g. --body-data) to avoid
// duplicate-flag panics from Go's stdlib flag package.
var reservedBodyFlagNames = map[string]bool{
	"output":    true,
	"all":       true,
	"data":      true,
	"data-file": true,
}

// subResourceHelpTemplate renders actions and sub-resources as separate sections.
var subResourceHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} command [command options] [arguments...]

COMMANDS:{{range .VisibleCommands}}{{if not .Category}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}

SUB-RESOURCES:{{range .VisibleCommands}}{{if .Category}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}

OPTIONS:
   {{range .VisibleFlagCategories}}{{range .Flags}}{{.}}
   {{end}}{{end}}
`

// BuildCommands converts parsed OpenAPI operations into a cli.Command tree grouped by tag.
func BuildCommands(spec *Spec) []*cli.Command {
	ops := collectOperations(spec)
	grouped := groupByTag(ops)

	tagDescriptions := make(map[string]string)
	for _, t := range spec.Tags {
		tagDescriptions[tagToCommand(t.Name)] = firstLine(t.Description)
	}

	var commands []*cli.Command
	for _, cmdName := range sortedKeys(grouped) {
		actions := grouped[cmdName]
		subCmds := buildTagSubcommands(spec, actions)
		sort.Slice(subCmds, func(i, j int) bool { return subCmds[i].Name < subCmds[j].Name })
		desc := tagDescriptions[cmdName]
		if desc == "" {
			desc = cmdName + " operations"
		}
		cmd := &cli.Command{
			Name:        cmdName,
			Usage:       desc,
			Subcommands: subCmds,
		}
		for _, sc := range subCmds {
			if sc.Category != "" {
				cmd.CustomHelpTemplate = subResourceHelpTemplate
				break
			}
		}
		commands = append(commands, cmd)
	}
	return commands
}

func collectOperations(spec *Spec) []resolvedOp {
	var ops []resolvedOp
	for path, item := range spec.Paths {
		methods := []struct {
			m  string
			op *Operation
		}{
			{"GET", item.Get},
			{"POST", item.Post},
			{"PATCH", item.Patch},
			{"PUT", item.Put},
			{"DELETE", item.Delete},
		}
		for _, me := range methods {
			if me.op == nil {
				continue
			}
			tag := "other"
			if len(me.op.Tags) > 0 {
				tag = me.op.Tags[0]
			}
			ops = append(ops, resolvedOp{
				tag:        tag,
				action:     operationAction(me.op.OperationID),
				method:     me.m,
				path:       path,
				op:         me.op,
				pathParams: item.Parameters,
			})
		}
	}
	return ops
}

func groupByTag(ops []resolvedOp) map[string][]resolvedOp {
	grouped := make(map[string][]resolvedOp)
	for _, op := range ops {
		cmdName := tagToCommand(op.tag)
		grouped[cmdName] = append(grouped[cmdName], op)
	}
	return grouped
}

// buildTagSubcommands splits a tag's operations into primary resource actions
// and nested sub-resource groups.
func buildTagSubcommands(spec *Spec, ops []resolvedOp) []*cli.Command {
	primary := detectPrimaryResource(ops)

	var primaryOps []resolvedOp
	subResourceOps := make(map[string][]resolvedOp)

	for _, op := range ops {
		suffix := extractResourceSuffix(op.op.OperationID)
		subRes := subResourceName(suffix, primary)
		if subRes == "" {
			primaryOps = append(primaryOps, op)
		} else {
			subResourceOps[subRes] = append(subResourceOps[subRes], op)
		}
	}

	// Resolve action-name collisions symmetrically: when two or more
	// operations under the same tag collapse to the same short action, expand
	// ALL of them to their full OperationID. The previous "first one wins"
	// pass produced a different command surface depending on the order of map
	// iteration in collectOperations, which depended on whether the user's
	// config file had been loaded -- the same binary exposed different
	// commands in the two states.
	//
	// The formerly motivating case -- `get-current-infrastructure-provider`
	// and `get-current-infrastructure-provider-stats` both collapsing to
	// `get` -- no longer collides: get-current-* singletons now map to
	// distinct `current` / `stats` actions in operationAction. This guard
	// stays for any future tag whose operations still collide on a short
	// action.
	actionCounts := make(map[string]int)
	for _, op := range primaryOps {
		actionCounts[op.action]++
	}
	for i := range primaryOps {
		if actionCounts[primaryOps[i].action] > 1 {
			primaryOps[i].action = primaryOps[i].op.OperationID
		}
	}

	var cmds []*cli.Command
	for _, op := range primaryOps {
		cmds = append(cmds, buildActionCommand(spec, op, ""))
	}

	subResNames := make([]string, 0, len(subResourceOps))
	for name := range subResourceOps {
		subResNames = append(subResNames, name)
	}
	sort.Strings(subResNames)

	for _, name := range subResNames {
		subOps := subResourceOps[name]
		subCmds := make([]*cli.Command, 0, len(subOps))
		for _, op := range subOps {
			subCmds = append(subCmds, buildActionCommand(spec, op, name))
		}
		sort.Slice(subCmds, func(i, j int) bool { return subCmds[i].Name < subCmds[j].Name })

		usage := name + " operations"
		if len(subCmds) == 1 {
			usage = subCmds[0].Usage
		}
		cmds = append(cmds, &cli.Command{
			Name:        name,
			Category:    "Sub-resources",
			Usage:       usage,
			Subcommands: subCmds,
		})
	}

	return cmds
}

func detectPrimaryResource(ops []resolvedOp) string {
	counts := make(map[string]int)
	for _, op := range ops {
		suffix := extractResourceSuffix(op.op.OperationID)
		counts[suffix]++
	}
	best := ""
	bestCount := 0
	for suffix, count := range counts {
		if count > bestCount || (count == bestCount && len(suffix) < len(best)) {
			bestCount = count
			best = suffix
		}
	}
	return best
}

func extractResourceSuffix(opID string) string {
	prefixes := []string{
		"batch-create-", "batch-update-",
		"get-all-", "get-current-",
		"create-", "update-", "delete-", "get-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(opID, p) {
			return opID[len(p):]
		}
	}
	return opID
}

func subResourceName(suffix, primary string) string {
	if suffix == primary {
		return ""
	}
	if suffix == primary+"s" || suffix == primary+"es" {
		return ""
	}
	if strings.HasPrefix(suffix, primary+"-") {
		remainder := suffix[len(primary)+1:]
		if isActionModifier(remainder) {
			return ""
		}
		return remainder
	}
	if strings.HasSuffix(suffix, "-"+primary) {
		return suffix[:len(suffix)-len(primary)-1]
	}
	return suffix
}

func isActionModifier(s string) bool {
	switch s {
	case "status-history", "stats":
		return true
	}
	return false
}

func isListAction(action string) bool {
	return action == "list" || strings.HasPrefix(action, "list-")
}

func buildActionCommand(spec *Spec, ro resolvedOp, subResource string) *cli.Command {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:   "output",
			Usage:  "Output format: json, yaml, table",
			Value:  "json",
			Action: validateOutputFlag,
		},
	}

	isList := isListAction(ro.action)
	if isList {
		flags = append(flags, &cli.BoolFlag{
			Name:  "all",
			Usage: "Fetch all pages of results",
		})
	}

	var argParams []string

	allParams := append([]Parameter{}, ro.pathParams...)
	allParams = append(allParams, ro.op.Parameters...)

	for _, p := range allParams {
		if p.Name == "org" {
			continue
		}
		if p.In == "path" {
			argParams = append(argParams, p.Name)
			continue
		}
		if p.In == "query" {
			flags = append(flags, paramToFlag(p))
		}
	}

	var bodyFields []bodyField

	hasBody := ro.op.RequestBody != nil
	if hasBody {
		flags = append(flags,
			&cli.StringFlag{
				Name:  "data",
				Usage: "Request body as inline JSON",
			},
			&cli.StringFlag{
				Name:  "data-file",
				Usage: "Path to a JSON file containing the request body (use - for stdin)",
			},
		)
		if schema := spec.RequestBodySchema(ro.op); schema != nil {
			reqSet := make(map[string]bool)
			for _, r := range schema.Required {
				reqSet[r] = true
			}
			for name, prop := range schema.Properties {
				resolved := spec.ResolveSchema(prop)
				if resolved == nil || resolved.Type == "object" || resolved.Type == "array" {
					continue
				}
				flagName := toKebab(name)
				// Prefix body properties whose kebab-cased name collides with
				// flags owned by the CLI wrapper. Without this, urfave/cli
				// calls flag.StringVar twice with the same name and Go's flag
				// package panics with "create flag redefined: data" at command
				// setup time (e.g. dpu-extension-service create has a body
				// property named "data"). The prefixed flag (--body-data)
				// stays distinct from the JSON wrapper flag (--data).
				if reservedBodyFlagNames[flagName] {
					flagName = "body-" + flagName
				}
				usage := name
				if reqSet[name] {
					usage += " (required)"
				}
				bodyFields = append(bodyFields, bodyField{
					jsonName: name,
					flagName: flagName,
					schema:   resolved,
				})
				flags = append(flags, schemaToFlag(flagName, usage, resolved))
			}
		}
	}

	sort.Slice(flags, func(i, j int) bool {
		return flags[i].Names()[0] < flags[j].Names()[0]
	})

	usageText := binaryName + " " + tagToCommand(ro.tag)
	if subResource != "" {
		usageText += " " + subResource
	}
	usageText += " " + ro.action
	for _, ap := range argParams {
		usageText += " <" + ap + ">"
	}

	summary := ro.op.Summary
	if summary == "" {
		summary = ro.op.OperationID
	}

	return &cli.Command{
		Name:      ro.action,
		Usage:     summary,
		UsageText: usageText,
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if err := detectMisorderedFlags(c, argParams, usageText); err != nil {
				return err
			}

			client, err := clientFromContext(c)
			if err != nil {
				return err
			}

			pathParams := make(map[string]string)
			for i, ap := range argParams {
				if c.NArg() <= i {
					return fmt.Errorf("missing required argument: <%s>", ap)
				}
				pathParams[ap] = c.Args().Get(i)
			}

			queryParams := make(map[string]string)
			for _, p := range allParams {
				if p.In != "query" {
					continue
				}
				if v := readFlagValue(c, p); v != "" {
					queryParams[p.Name] = v
				}
			}

			var body []byte
			if hasBody {
				body, err = buildRequestBody(c, bodyFields)
				if err != nil {
					return err
				}
			}

			if isList && c.Bool("all") {
				return fetchAllPages(client, ro.method, ro.path, pathParams, queryParams, c.String("output"))
			}

			respBody, respHeaders, err := client.Do(ro.method, ro.path, pathParams, queryParams, body)
			if err != nil {
				return err
			}

			printPaginationSummary(respHeaders)

			if len(respBody) == 0 {
				return nil
			}

			return FormatOutput(respBody, c.String("output"))
		},
	}
}

// detectMisorderedFlags returns a helpful error when urfave/cli's stdlib flag
// parser stopped at a positional and left flag-like tokens in c.Args(). Go's
// flag package stops parsing at the first non-flag argument, so anything the
// user placed after a positional is silently ignored -- which on update/create
// operations surfaces as confusing server-side errors like "no updates
// specified". Catching it client-side turns a silent drop into a clear usage
// hint.
func detectMisorderedFlags(c *cli.Context, argParams []string, usageText string) error {
	return detectMisorderedFlagsInArgs(c.Args().Slice(), argParams, usageText)
}

// detectMisorderedFlagsInArgs is the pure-function core of detectMisorderedFlags,
// extracted so it can be exercised directly from tests without building a cli.Context.
func detectMisorderedFlagsInArgs(args, argParams []string, usageText string) error {
	isFlagLike := func(s string) bool {
		return strings.HasPrefix(s, "-") && len(s) > 1
	}

	// Default: extras start past all expected positionals. But if a flag-like
	// token appears inside the positional slots on a multi-positional command
	// (e.g. `create <instanceTypeId> --data={}`, where urfave would otherwise
	// pass --data={} through as the second path param), split earlier so the
	// flag is detected rather than silently consumed into the URL path.
	split := len(argParams)
	for i := 1; i < len(args) && i < len(argParams); i++ {
		if isFlagLike(args[i]) {
			split = i
			break
		}
	}
	if len(args) <= split {
		return nil
	}
	extras := args[split:]

	var misplacedFlags, extraPositionals []string
	for _, a := range extras {
		if isFlagLike(a) {
			name := a
			if eq := strings.Index(a, "="); eq >= 0 {
				name = a[:eq]
			}
			misplacedFlags = append(misplacedFlags, name)
		} else {
			extraPositionals = append(extraPositionals, a)
		}
	}

	if len(misplacedFlags) == 0 && len(extraPositionals) == 0 {
		return nil
	}

	// Rewrite the usage line so the hint shows exactly where flags belong.
	hint := usageText
	if len(argParams) > 0 {
		tail := ""
		for _, ap := range argParams {
			tail += " <" + ap + ">"
		}
		if idx := strings.Index(usageText, tail); idx >= 0 {
			hint = usageText[:idx] + " [flags...]" + tail
		}
	}

	var msg strings.Builder
	if len(misplacedFlags) > 0 {
		fmt.Fprintf(&msg, "flag(s) %s placed after a positional argument; urfave/cli (stdlib flag) stops parsing flags at the first positional, so these flags are being ignored.\n",
			strings.Join(misplacedFlags, ", "))
		fmt.Fprintf(&msg, "Move all flags before positionals, e.g.\n  %s\n", hint)
	}
	if len(extraPositionals) > 0 {
		if msg.Len() > 0 {
			msg.WriteString("Also: ")
		}
		fmt.Fprintf(&msg, "unexpected positional argument(s): %s (expected %d: %s)",
			strings.Join(extraPositionals, ", "),
			len(argParams),
			strings.Join(argParams, ", "))
	}
	return fmt.Errorf("%s", strings.TrimRight(msg.String(), "\n"))
}

func readFlagValue(c *cli.Context, p Parameter) string {
	flagName := toKebab(p.Name)
	if p.Schema == nil {
		return c.String(flagName)
	}
	switch p.Schema.Type {
	case "integer":
		if c.IsSet(flagName) {
			return fmt.Sprintf("%d", c.Int(flagName))
		}
		return ""
	case "boolean":
		if c.IsSet(flagName) {
			return fmt.Sprintf("%t", c.Bool(flagName))
		}
		return ""
	default:
		return c.String(flagName)
	}
}

func schemaToFlag(flagName, usage string, schema *Schema) cli.Flag {
	return &cli.StringFlag{Name: flagName, Usage: usage}
}

func buildRequestBody(c *cli.Context, bodyFields []bodyField) ([]byte, error) {
	data := c.String("data")
	dataFile := c.String("data-file")
	body, err := ReadBodyInput(data, dataFile)
	if err != nil {
		return nil, err
	}
	if body != nil {
		return body, nil
	}

	obj := make(map[string]interface{})
	for _, bf := range bodyFields {
		v := c.String(bf.flagName)
		if v == "" {
			continue
		}
		val, err := coerceValue(v, bf.schema.Type)
		if err != nil {
			return nil, fmt.Errorf("flag --%s: %w", bf.flagName, err)
		}
		obj[bf.jsonName] = val
	}

	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj)
}

type paginationHeader struct {
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
	Total      int `json:"total"`
}

func parsePaginationHeader(headers http.Header) *paginationHeader {
	raw := headers.Get("X-Pagination")
	if raw == "" {
		return nil
	}
	var h paginationHeader
	if json.Unmarshal([]byte(raw), &h) != nil {
		return nil
	}
	return &h
}

func printPaginationSummary(headers http.Header) {
	h := parsePaginationHeader(headers)
	if h == nil {
		return
	}
	pageCount := 1
	if h.PageSize > 0 && h.Total > 0 {
		pageCount = (h.Total + h.PageSize - 1) / h.PageSize
	}
	if pageCount > 1 {
		fmt.Fprintf(os.Stderr, "Page %d/%d (%d items, %d total). Use --all to fetch everything.\n",
			h.PageNumber, pageCount, h.PageSize, h.Total)
	} else {
		fmt.Fprintf(os.Stderr, "%d items\n", h.Total)
	}
}

func fetchAllPages(client *Client, method, path string, pathParams, queryParams map[string]string, outputFormat string) error {
	const maxPageSize = 100
	const maxPages = 1000
	pageNumber := 1

	if queryParams == nil {
		queryParams = make(map[string]string)
	}
	queryParams["pageSize"] = strconv.Itoa(maxPageSize)

	var allItems []json.RawMessage
	totalFromHeader := 0

	for {
		queryParams["pageNumber"] = strconv.Itoa(pageNumber)

		respBody, respHeaders, err := client.Do(method, path, pathParams, queryParams, nil)
		if err != nil {
			return err
		}

		var pageItems []json.RawMessage
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &pageItems); err != nil {
				return FormatOutput(respBody, outputFormat)
			}
		}
		allItems = append(allItems, pageItems...)

		h := parsePaginationHeader(respHeaders)
		if h != nil {
			totalFromHeader = h.Total
		}

		if h != nil && h.Total > 0 && len(allItems) >= h.Total {
			break
		}
		if len(pageItems) < maxPageSize {
			break
		}

		pageNumber++
		if pageNumber > maxPages {
			fmt.Fprintf(os.Stderr, "Warning: stopped after %d pages (%d items). Consider adding filters to reduce the number of fetched items.\n", maxPages, len(allItems))
			break
		}
	}

	if totalFromHeader > 0 {
		fmt.Fprintf(os.Stderr, "Fetched all %d items\n", totalFromHeader)
	} else {
		fmt.Fprintf(os.Stderr, "Fetched %d items\n", len(allItems))
	}

	merged, err := json.Marshal(allItems)
	if err != nil {
		return err
	}
	return FormatOutput(merged, outputFormat)
}

func coerceValue(v string, schemaType SchemaType) (interface{}, error) {
	switch schemaType {
	case "integer":
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("expected integer, got %q", v)
		}
		return n, nil
	case "boolean":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("expected boolean, got %q", v)
		}
		return b, nil
	case "number":
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("expected number, got %q", v)
		}
		return f, nil
	default:
		return v, nil
	}
}

func clientFromContext(c *cli.Context) (*Client, error) {
	cfg, _ := LoadConfig()
	ApplyEnvOverrides(cfg)

	tokenCommand := c.String("token-command")
	tokenCommandFromConfig := false
	if tokenCommand == "" && HasTokenCommandConfig(cfg) {
		tokenCommand = cfg.Auth.TokenCommand
		tokenCommandFromConfig = true
	}

	token := c.String("token")
	if token == "" {
		if tokenCommand != "" && !tokenCommandFromConfig {
			token = ""
		} else {
			token = GetAuthToken(cfg)
			if token == "" {
				var refreshErr error
				token, refreshErr = AutoRefreshToken(cfg)
				if refreshErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: auto-refresh token failed: %v\n", refreshErr)
				}
			}
		}
	}

	resolved, err := ResolveToken(token, tokenCommand)
	if err != nil {
		return nil, err
	}

	if resolved == "" {
		return nil, fmt.Errorf("no token available; run '%s login' or set --token / NICO_TOKEN", binaryName)
	}

	// Explicit flag > config > flag default (spec server URL).
	baseURL := cfg.API.Base
	if c.IsSet("base-url") {
		baseURL = c.String("base-url")
	}
	if baseURL == "" {
		baseURL = c.String("base-url")
	}

	org := cfg.API.Org
	if c.IsSet("org") {
		org = c.String("org")
	}
	if org == "" {
		return nil, fmt.Errorf("--org is required (or set api.org in config)")
	}

	apiName := cfg.API.Name
	if c.IsSet("api-name") {
		apiName = c.String("api-name")
	}
	if apiName == "" {
		apiName = "nico"
	}

	debug := c.Bool("debug")
	log := logrus.NewEntry(logrus.StandardLogger())

	client := NewClient(baseURL, org, resolved, log, debug)
	client.APIName = apiName
	if tokenCommand != "" {
		configPath := ConfigPath()
		client.TokenRefresh = func() (string, error) {
			if tokenCommandFromConfig {
				return LoginWithTokenCommand(cfg, configPath, tokenCommand)
			}
			return ExecuteTokenCommand(tokenCommand)
		}
	}
	return client, nil
}

func paramToFlag(p Parameter) cli.Flag {
	flagName := toKebab(p.Name)
	usage := p.Description
	if p.Schema != nil && len(p.Schema.Enum) > 0 {
		usage += " [" + strings.Join(p.Schema.Enum, ", ") + "]"
	}

	if p.Schema != nil {
		switch p.Schema.Type {
		case "integer":
			f := &cli.IntFlag{Name: flagName, Usage: usage}
			if p.Schema.Default != nil {
				if v, ok := p.Schema.Default.(int); ok {
					f.Value = v
				}
			}
			return f
		case "boolean":
			return &cli.BoolFlag{Name: flagName, Usage: usage}
		}
	}

	return &cli.StringFlag{Name: flagName, Usage: usage}
}

func tagToCommand(tag string) string {
	return toKebab(tag)
}

func operationAction(opID string) string {
	patterns := []struct {
		prefix string
		action string
		// bare is the action for a getter prefix (action == "") when the
		// operation has no -stats / -status-history suffix. A plain
		// get-<resource> is the `get` action; a get-current-<resource>
		// singleton getter is the `current` action so the generated command
		// matches the REST /current path and the interactive TUI command name
		// (e.g. `tenant current`, `infrastructure-provider current`).
		bare string
	}{
		{prefix: "batch-create-", action: "batch-create"},
		{prefix: "batch-update-", action: "batch-update"},
		{prefix: "get-all-", action: "list"},
		{prefix: "get-current-", bare: "current"},
		{prefix: "create-", action: "create"},
		{prefix: "update-", action: "update"},
		{prefix: "delete-", action: "delete"},
		{prefix: "get-", bare: "get"},
	}

	for _, p := range patterns {
		if !strings.HasPrefix(opID, p.prefix) {
			continue
		}
		if p.action != "" {
			return p.action
		}
		// Getter prefix: a -stats or -status-history endpoint collapses to
		// its own action so a resource's getter and its stats / history
		// endpoints stay distinct commands instead of colliding on one action
		// (which would force both to expand to their full operationId). This
		// applies to both get- and get-current-.
		suffix := opID[len(p.prefix):]
		if strings.HasSuffix(suffix, "-status-history") {
			return "status-history"
		}
		if strings.HasSuffix(suffix, "-stats") {
			return "stats"
		}
		return p.bare
	}

	return opID
}

func toKebab(s string) string {
	if strings.Contains(s, " ") {
		parts := strings.Fields(s)
		for i := range parts {
			parts[i] = strings.ToLower(parts[i])
		}
		return strings.Join(parts, "-")
	}

	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' {
				result = append(result, '-')
			}
			j := i + 1
			for j < len(s) && s[j] >= 'A' && s[j] <= 'Z' {
				j++
			}
			for k := i; k < j; k++ {
				result = append(result, s[k]-'A'+'a')
			}
			i = j - 1
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func sortedKeys(m map[string][]resolvedOp) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
