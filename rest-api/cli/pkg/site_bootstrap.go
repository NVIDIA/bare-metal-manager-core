// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	urfavecli "github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

const (
	sitePrerequisiteAPIVersion = "nico.nvidia.com/v1alpha1"
	sitePrerequisiteKind       = "SitePrerequisites"
	bootstrapPageSize          = 100
	bootstrapMaxPages          = 1000
)

var (
	bootstrapAliasPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	bootstrapRefPattern   = regexp.MustCompile(`\$\{([^{}]+)\}`)

	errInvalidBootstrapManifest  = errors.New("invalid site prerequisite manifest")
	errInvalidBootstrapResource  = errors.New("invalid site prerequisite resource")
	errBootstrapReference        = errors.New("invalid site prerequisite reference")
	errBootstrapResponse         = errors.New("invalid site prerequisite API response")
	errBootstrapDrift            = errors.New("site prerequisite resource drift")
	errBootstrapClientRequired   = errors.New("REST client is required")
	errBootstrapManifestRequired = errors.New("manifest is required")
)

// sitePrerequisiteManifest is a declarative, replayable site bring-up plan.
// Each resource request is passed through to its existing REST endpoint after
// ${...} references have been resolved from resources earlier in the plan.
type sitePrerequisiteManifest struct {
	APIVersion    string                        `yaml:"apiVersion"`
	Kind          string                        `yaml:"kind"`
	Provider      bootstrapOrganization         `yaml:"provider"`
	Tenant        bootstrapOrganization         `yaml:"tenant"`
	Site          *bootstrapResource            `yaml:"site"`
	IPBlocks      map[string]*bootstrapResource `yaml:"ipBlocks,omitempty"`
	InstanceTypes map[string]*bootstrapResource `yaml:"instanceTypes,omitempty"`
	Allocations   map[string]*bootstrapResource `yaml:"allocations,omitempty"`
	VPCs          map[string]*bootstrapResource `yaml:"vpcs,omitempty"`
	VPCPrefixes   map[string]*bootstrapResource `yaml:"vpcPrefixes,omitempty"`
	Instances     map[string]*bootstrapResource `yaml:"instances,omitempty"`
}

type bootstrapOrganization struct {
	Org string `yaml:"org"`
	ID  string `yaml:"id,omitempty"`
}

type bootstrapResource struct {
	ID      string         `yaml:"id,omitempty"`
	Request map[string]any `yaml:"request"`
}

type bootstrapEndpoint struct {
	category       string
	displayName    string
	collectionPath string
	itemPath       string
	itemIDParam    string
	providerScoped bool
}

var (
	bootstrapSiteEndpoint = bootstrapEndpoint{
		category:       "site",
		displayName:    "site",
		collectionPath: "/v2/org/{org}/nico/site",
		itemPath:       "/v2/org/{org}/nico/site/{siteId}",
		itemIDParam:    "siteId",
		providerScoped: true,
	}
	bootstrapIPBlockEndpoint = bootstrapEndpoint{
		category:       "ipBlocks",
		displayName:    "IP block",
		collectionPath: "/v2/org/{org}/nico/ipblock",
		itemPath:       "/v2/org/{org}/nico/ipblock/{ipBlockId}",
		itemIDParam:    "ipBlockId",
		providerScoped: true,
	}
	bootstrapInstanceTypeEndpoint = bootstrapEndpoint{
		category:       "instanceTypes",
		displayName:    "instance type",
		collectionPath: "/v2/org/{org}/nico/instance/type",
		itemPath:       "/v2/org/{org}/nico/instance/type/{instanceTypeId}",
		itemIDParam:    "instanceTypeId",
		providerScoped: true,
	}
	bootstrapAllocationEndpoint = bootstrapEndpoint{
		category:       "allocations",
		displayName:    "allocation",
		collectionPath: "/v2/org/{org}/nico/allocation",
		itemPath:       "/v2/org/{org}/nico/allocation/{allocationId}",
		itemIDParam:    "allocationId",
		providerScoped: true,
	}
	bootstrapVPCEndpoint = bootstrapEndpoint{
		category:       "vpcs",
		displayName:    "VPC",
		collectionPath: "/v2/org/{org}/nico/vpc",
		itemPath:       "/v2/org/{org}/nico/vpc/{vpcId}",
		itemIDParam:    "vpcId",
	}
	bootstrapVPCPrefixEndpoint = bootstrapEndpoint{
		category:       "vpcPrefixes",
		displayName:    "VPC prefix",
		collectionPath: "/v2/org/{org}/nico/vpc-prefix",
		itemPath:       "/v2/org/{org}/nico/vpc-prefix/{vpcPrefixId}",
		itemIDParam:    "vpcPrefixId",
	}
	bootstrapInstanceEndpoint = bootstrapEndpoint{
		category:       "instances",
		displayName:    "instance",
		collectionPath: "/v2/org/{org}/nico/instance",
		itemPath:       "/v2/org/{org}/nico/instance/{instanceId}",
		itemIDParam:    "instanceId",
	}
)

func addSiteBootstrapCommand(commands []*urfavecli.Command) []*urfavecli.Command {
	for _, command := range commands {
		if command.Name != "site" {
			continue
		}
		command.Subcommands = append(command.Subcommands, siteBootstrapCommand())
		sort.Slice(command.Subcommands, func(i, j int) bool {
			return command.Subcommands[i].Name < command.Subcommands[j].Name
		})
		return commands
	}

	return append(commands, &urfavecli.Command{
		Name:        "site",
		Usage:       "site operations",
		Subcommands: []*urfavecli.Command{siteBootstrapCommand()},
	})
}

func siteBootstrapCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "bootstrap",
		Usage:     "Create or verify site prerequisite resources from a manifest",
		UsageText: binaryName + " site bootstrap --file <site-prerequisites.yaml> [--output-file <resolved.yaml>]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:     "file",
				Aliases:  []string{"f"},
				Usage:    "Input YAML manifest path (use - for stdin)",
				Required: true,
			},
			&urfavecli.StringFlag{
				Name:  "output-file",
				Usage: "Write the replayable manifest with resolved resource IDs to this path (use - for stdout)",
				Value: "-",
			},
		},
		Action: func(c *urfavecli.Context) error {
			stdin := io.Reader(os.Stdin)
			stdout := io.Writer(os.Stdout)
			stderr := io.Writer(os.Stderr)
			if c.App.Reader != nil {
				stdin = c.App.Reader
			}
			if c.App.Writer != nil {
				stdout = c.App.Writer
			}
			if c.App.ErrWriter != nil {
				stderr = c.App.ErrWriter
			}

			manifest, err := readSitePrerequisiteManifest(c.String("file"), stdin)
			if err != nil {
				return err
			}

			if manifest.Provider.Org != "" && c.String("org") == "" {
				if err := c.Set("org", manifest.Provider.Org); err != nil {
					return fmt.Errorf("using provider.org as the CLI organization: %w", err)
				}
			}

			client, err := clientFromContext(c)
			if err != nil {
				return err
			}
			if manifest.Provider.Org == "" {
				manifest.Provider.Org = client.Org
			}

			if err := bootstrapSitePrerequisites(client, manifest, stderr); err != nil {
				return fmt.Errorf("bootstrapping site prerequisites: %w", err)
			}

			if err := writeSitePrerequisiteManifest(c.String("output-file"), stdout, manifest); err != nil {
				return err
			}
			return nil
		},
	}
}

func readSitePrerequisiteManifest(filename string, stdin io.Reader) (*sitePrerequisiteManifest, error) {
	var data []byte
	var err error
	if filename == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return nil, fmt.Errorf("reading site prerequisite manifest: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	manifest := &sitePrerequisiteManifest{}
	if err := decoder.Decode(manifest); err != nil {
		return nil, fmt.Errorf("parsing site prerequisite manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("parsing site prerequisite manifest: %w: multiple YAML documents are not supported", errInvalidBootstrapManifest)
		}
		return nil, fmt.Errorf("parsing site prerequisite manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return nil, fmt.Errorf("validating site prerequisite manifest: %w", err)
	}
	return manifest, nil
}

func writeSitePrerequisiteManifest(filename string, stdout io.Writer, manifest *sitePrerequisiteManifest) error {
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encoding resolved site prerequisite manifest: %w", err)
	}
	if filename == "-" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("writing resolved site prerequisite manifest: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		return fmt.Errorf("writing resolved site prerequisite manifest: %w", err)
	}
	return nil
}

func (manifest *sitePrerequisiteManifest) validate() error {
	if manifest.APIVersion != sitePrerequisiteAPIVersion {
		return fmt.Errorf("%w: apiVersion must be %q", errInvalidBootstrapManifest, sitePrerequisiteAPIVersion)
	}
	if manifest.Kind != sitePrerequisiteKind {
		return fmt.Errorf("%w: kind must be %q", errInvalidBootstrapManifest, sitePrerequisiteKind)
	}
	if manifest.Tenant.Org == "" {
		return fmt.Errorf("%w: tenant.org is required", errInvalidBootstrapManifest)
	}
	if manifest.Site == nil {
		return fmt.Errorf("%w: site is required", errInvalidBootstrapManifest)
	}
	if err := validateBootstrapResource("site", manifest.Site); err != nil {
		return err
	}

	groups := []struct {
		name      string
		resources map[string]*bootstrapResource
	}{
		{name: "ipBlocks", resources: manifest.IPBlocks},
		{name: "instanceTypes", resources: manifest.InstanceTypes},
		{name: "allocations", resources: manifest.Allocations},
		{name: "vpcs", resources: manifest.VPCs},
		{name: "vpcPrefixes", resources: manifest.VPCPrefixes},
		{name: "instances", resources: manifest.Instances},
	}
	for _, group := range groups {
		for alias, resource := range group.resources {
			if !bootstrapAliasPattern.MatchString(alias) {
				return fmt.Errorf("%w: %s alias %q must start with a letter and contain only letters, digits, underscores, or hyphens", errInvalidBootstrapManifest, group.name, alias)
			}
			if err := validateBootstrapResource(group.name+"."+alias, resource); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateBootstrapResource(path string, resource *bootstrapResource) error {
	if resource == nil {
		return fmt.Errorf("%w: %s must not be null", errInvalidBootstrapResource, path)
	}
	if len(resource.Request) == 0 {
		return fmt.Errorf("%w: %s.request is required", errInvalidBootstrapResource, path)
	}
	name, ok := resource.Request["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: %s.request.name is required", errInvalidBootstrapResource, path)
	}
	return nil
}

func bootstrapSitePrerequisites(client *Client, manifest *sitePrerequisiteManifest, progress io.Writer) error {
	if client == nil {
		return errBootstrapClientRequired
	}
	if manifest == nil {
		return errBootstrapManifestRequired
	}
	if manifest.Provider.Org == "" {
		return fmt.Errorf("%w: provider.org is required when applying a manifest", errInvalidBootstrapManifest)
	}
	if progress == nil {
		progress = io.Discard
	}

	originalOrg := client.Org
	defer func() {
		client.Org = originalOrg
	}()

	context := map[string]any{}
	provider, err := bootstrapOrganizationCurrent(client, manifest.Provider.Org, "/v2/org/{org}/nico/infrastructure-provider/current", "provider", progress)
	if err != nil {
		return err
	}
	manifest.Provider.ID, err = bootstrapResponseID(provider)
	if err != nil {
		return fmt.Errorf("resolving provider: %w", err)
	}
	context["provider"] = provider

	tenant, err := bootstrapOrganizationCurrent(client, manifest.Tenant.Org, "/v2/org/{org}/nico/tenant/current", "tenant", progress)
	if err != nil {
		return err
	}
	manifest.Tenant.ID, err = bootstrapResponseID(tenant)
	if err != nil {
		return fmt.Errorf("resolving tenant: %w", err)
	}
	context["tenant"] = tenant

	site, err := ensureBootstrapResource(client, manifest, bootstrapSiteEndpoint, "site", manifest.Site, context, progress)
	if err != nil {
		return err
	}
	context["site"] = site

	groups := []struct {
		endpoint  bootstrapEndpoint
		resources map[string]*bootstrapResource
	}{
		{endpoint: bootstrapIPBlockEndpoint, resources: manifest.IPBlocks},
		{endpoint: bootstrapInstanceTypeEndpoint, resources: manifest.InstanceTypes},
		{endpoint: bootstrapAllocationEndpoint, resources: manifest.Allocations},
		{endpoint: bootstrapVPCEndpoint, resources: manifest.VPCs},
		{endpoint: bootstrapVPCPrefixEndpoint, resources: manifest.VPCPrefixes},
		{endpoint: bootstrapInstanceEndpoint, resources: manifest.Instances},
	}
	for _, group := range groups {
		resolved := map[string]any{}
		context[group.endpoint.category] = resolved
		aliases := make([]string, 0, len(group.resources))
		for alias := range group.resources {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		for _, alias := range aliases {
			response, err := ensureBootstrapResource(client, manifest, group.endpoint, alias, group.resources[alias], context, progress)
			if err != nil {
				return err
			}
			resolved[alias] = response
		}
	}
	return nil
}

func bootstrapOrganizationCurrent(client *Client, org, endpoint, displayName string, progress io.Writer) (map[string]any, error) {
	client.Org = org
	body, _, err := client.Do(http.MethodGet, endpoint, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("resolving %s for org %q: %w", displayName, org, err)
	}
	response, err := decodeBootstrapObject(body)
	if err != nil {
		return nil, fmt.Errorf("decoding %s for org %q: %w", displayName, org, err)
	}
	id, err := bootstrapResponseID(response)
	if err != nil {
		return nil, fmt.Errorf("resolving %s for org %q: %w", displayName, org, err)
	}
	fmt.Fprintf(progress, "resolved %s %s (%s)\n", displayName, org, id)
	return response, nil
}

func ensureBootstrapResource(client *Client, manifest *sitePrerequisiteManifest, endpoint bootstrapEndpoint, alias string, resource *bootstrapResource, context map[string]any, progress io.Writer) (map[string]any, error) {
	resolvedValue, err := resolveBootstrapValue(resource.Request, context)
	if err != nil {
		return nil, fmt.Errorf("resolving %s %q request: %w", endpoint.displayName, alias, err)
	}
	request, ok := resolvedValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("resolving %s %q request: %w: expected an object", endpoint.displayName, alias, errInvalidBootstrapResource)
	}
	resourcePath := endpoint.category
	if alias != endpoint.category {
		resourcePath += "." + alias
	}
	if err := validateBootstrapResource(resourcePath, &bootstrapResource{Request: request}); err != nil {
		return nil, fmt.Errorf("resolving %s %q request: %w", endpoint.displayName, alias, err)
	}
	name, _ := request["name"].(string)

	org := manifest.Tenant.Org
	if endpoint.providerScoped {
		org = manifest.Provider.Org
	}
	client.Org = org

	candidateID := resource.ID
	if candidateID == "" {
		candidateID, _ = request["id"].(string)
	}
	if candidateID != "" {
		response, err := getBootstrapResource(client, endpoint, candidateID)
		if err == nil {
			if err := verifyBootstrapResource(endpoint, alias, request, response); err != nil {
				return nil, err
			}
			resource.ID = candidateID
			fmt.Fprintf(progress, "reused %s %s (%s)\n", endpoint.displayName, name, candidateID)
			return response, nil
		}
		if !isBootstrapNotFound(err) {
			return nil, fmt.Errorf("retrieving %s %q by ID %q: %w", endpoint.displayName, alias, candidateID, err)
		}
	}

	response, found, err := findBootstrapResource(client, endpoint, request)
	if err != nil {
		return nil, fmt.Errorf("finding %s %q: %w", endpoint.displayName, alias, err)
	}
	if found {
		if err := verifyBootstrapResource(endpoint, alias, request, response); err != nil {
			return nil, err
		}
		resource.ID, err = bootstrapResponseID(response)
		if err != nil {
			return nil, fmt.Errorf("finding %s %q: %w", endpoint.displayName, alias, err)
		}
		fmt.Fprintf(progress, "reused %s %s (%s)\n", endpoint.displayName, name, resource.ID)
		return response, nil
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encoding %s %q request: %w", endpoint.displayName, alias, err)
	}
	body, _, err := client.Do(http.MethodPost, endpoint.collectionPath, nil, nil, requestBody)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
			response, found, findErr := findBootstrapResource(client, endpoint, request)
			if findErr == nil && found {
				if verifyErr := verifyBootstrapResource(endpoint, alias, request, response); verifyErr != nil {
					return nil, verifyErr
				}
				resource.ID, findErr = bootstrapResponseID(response)
				if findErr == nil {
					fmt.Fprintf(progress, "reused %s %s (%s) after a concurrent create\n", endpoint.displayName, name, resource.ID)
					return response, nil
				}
			}
		}
		return nil, fmt.Errorf("creating %s %q: %w", endpoint.displayName, alias, err)
	}
	response, err = decodeBootstrapObject(body)
	if err != nil {
		return nil, fmt.Errorf("decoding created %s %q: %w", endpoint.displayName, alias, err)
	}
	resource.ID, err = bootstrapResponseID(response)
	if err != nil {
		return nil, fmt.Errorf("decoding created %s %q: %w", endpoint.displayName, alias, err)
	}
	fmt.Fprintf(progress, "created %s %s (%s)\n", endpoint.displayName, name, resource.ID)
	return response, nil
}

func getBootstrapResource(client *Client, endpoint bootstrapEndpoint, id string) (map[string]any, error) {
	body, _, err := client.Do(http.MethodGet, endpoint.itemPath, map[string]string{endpoint.itemIDParam: id}, nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeBootstrapObject(body)
}

func findBootstrapResource(client *Client, endpoint bootstrapEndpoint, request map[string]any) (map[string]any, bool, error) {
	name, _ := request["name"].(string)
	var matches []map[string]any
	for page := 1; page <= bootstrapMaxPages; page++ {
		query := map[string]string{
			"query":      name,
			"pageNumber": strconv.Itoa(page),
			"pageSize":   strconv.Itoa(bootstrapPageSize),
		}
		body, _, err := client.Do(http.MethodGet, endpoint.collectionPath, nil, query, nil)
		if err != nil {
			return nil, false, err
		}
		items, err := decodeBootstrapList(body)
		if err != nil {
			return nil, false, err
		}
		for _, item := range items {
			if itemName, _ := item["name"].(string); itemName == name && bootstrapIdentityMatches(request, item) {
				matches = append(matches, item)
			}
		}
		if len(items) < bootstrapPageSize {
			break
		}
	}
	if len(matches) == 0 {
		return nil, false, nil
	}
	if len(matches) > 1 {
		return nil, false, fmt.Errorf("%w: multiple resources named %q matched the manifest scope", errInvalidBootstrapResource, name)
	}
	return matches[0], true, nil
}

func bootstrapIdentityMatches(request, actual map[string]any) bool {
	for _, field := range []string{"siteId", "tenantId", "vpcId"} {
		expected, requested := request[field]
		if !requested {
			continue
		}
		observed, present := actual[field]
		if !present || !bootstrapScalarEqual(expected, observed) {
			return false
		}
	}
	return true
}

func verifyBootstrapResource(endpoint bootstrapEndpoint, alias string, request, actual map[string]any) error {
	differences := bootstrapSubsetDifferences(request, actual, "")
	if len(differences) == 0 {
		return nil
	}
	return fmt.Errorf("%w: existing %s %q does not match the manifest request: %s", errBootstrapDrift, endpoint.displayName, alias, strings.Join(differences, "; "))
}

// bootstrapSubsetDifferences compares fields returned by the API with the
// requested fields. Write-only request fields are deliberately skipped when
// the API omits them from its response.
func bootstrapSubsetDifferences(expected, actual any, path string) []string {
	switch expectedValue := expected.(type) {
	case map[string]any:
		actualValue, ok := actual.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s has type %T, want object", bootstrapPath(path), actual)}
		}
		keys := make([]string, 0, len(expectedValue))
		for key := range expectedValue {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var differences []string
		for _, key := range keys {
			observed, present := actualValue[key]
			if !present {
				continue
			}
			differences = append(differences, bootstrapSubsetDifferences(expectedValue[key], observed, bootstrapJoinPath(path, key))...)
		}
		return differences
	case []any:
		actualValue, ok := actual.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s has type %T, want array", bootstrapPath(path), actual)}
		}
		if len(expectedValue) > len(actualValue) {
			return []string{fmt.Sprintf("%s has %d items, want at least %d", bootstrapPath(path), len(actualValue), len(expectedValue))}
		}
		var differences []string
		for index := range expectedValue {
			differences = append(differences, bootstrapSubsetDifferences(expectedValue[index], actualValue[index], bootstrapJoinPath(path, strconv.Itoa(index)))...)
		}
		return differences
	default:
		if bootstrapScalarEqual(expected, actual) {
			return nil
		}
		return []string{fmt.Sprintf("%s is %v, want %v", bootstrapPath(path), actual, expected)}
	}
}

func bootstrapScalarEqual(left, right any) bool {
	if left == nil {
		return right == nil
	}
	if right == nil {
		return false
	}
	leftEncoded, leftIsNumber := bootstrapNumberString(left)
	rightEncoded, rightIsNumber := bootstrapNumberString(right)
	if leftIsNumber != rightIsNumber {
		return false
	}
	if leftIsNumber {
		leftNumber, leftIsValid := new(big.Rat).SetString(leftEncoded)
		rightNumber, rightIsValid := new(big.Rat).SetString(rightEncoded)
		if !leftIsValid || !rightIsValid {
			return false
		}
		return leftNumber.Cmp(rightNumber) == 0
	}
	return reflect.TypeOf(left) == reflect.TypeOf(right) && reflect.DeepEqual(left, right)
}

func bootstrapNumberString(value any) (string, bool) {
	if number, ok := value.(json.Number); ok {
		return number.String(), true
	}

	reflected := reflect.ValueOf(value)
	kind := reflected.Kind()
	switch {
	case kind >= reflect.Int && kind <= reflect.Int64:
		return strconv.FormatInt(reflected.Int(), 10), true
	case kind >= reflect.Uint && kind <= reflect.Uintptr:
		return strconv.FormatUint(reflected.Uint(), 10), true
	case kind == reflect.Float32 || kind == reflect.Float64:
		return strconv.FormatFloat(reflected.Float(), 'g', -1, reflected.Type().Bits()), true
	default:
		return "", false
	}
}

func bootstrapJoinPath(base, element string) string {
	if base == "" {
		return element
	}
	return base + "." + element
}

func bootstrapPath(path string) string {
	if path == "" {
		return "value"
	}
	return path
}

func resolveBootstrapValue(value any, context map[string]any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		resolved := make(map[string]any, len(typed))
		for key, item := range typed {
			value, err := resolveBootstrapValue(item, context)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			resolved[key] = value
		}
		return resolved, nil
	case []any:
		resolved := make([]any, len(typed))
		for index, item := range typed {
			value, err := resolveBootstrapValue(item, context)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", index, err)
			}
			resolved[index] = value
		}
		return resolved, nil
	case string:
		matches := bootstrapRefPattern.FindAllStringSubmatchIndex(typed, -1)
		lastMatchEnd := 0
		for _, match := range matches {
			if bootstrapReferenceSyntaxMalformed(typed[lastMatchEnd:match[0]]) {
				return nil, fmt.Errorf("%w: malformed reference in %q", errBootstrapReference, typed)
			}
			lastMatchEnd = match[1]
		}
		if bootstrapReferenceSyntaxMalformed(typed[lastMatchEnd:]) {
			return nil, fmt.Errorf("%w: malformed reference in %q", errBootstrapReference, typed)
		}
		if len(matches) == 0 {
			return typed, nil
		}
		if len(matches) == 1 && matches[0][0] == 0 && matches[0][1] == len(typed) {
			return lookupBootstrapReference(context, typed[matches[0][2]:matches[0][3]])
		}

		var result strings.Builder
		last := 0
		for _, match := range matches {
			result.WriteString(typed[last:match[0]])
			resolved, err := lookupBootstrapReference(context, typed[match[2]:match[3]])
			if err != nil {
				return nil, err
			}
			result.WriteString(fmt.Sprint(resolved))
			last = match[1]
		}
		result.WriteString(typed[last:])
		return result.String(), nil
	default:
		return value, nil
	}
}

func bootstrapReferenceSyntaxMalformed(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "}")
}

func lookupBootstrapReference(context map[string]any, reference string) (any, error) {
	parts := strings.Split(reference, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("%w: empty reference %q", errBootstrapReference, reference)
	}
	var current any = context
	for _, part := range parts {
		switch typed := current.(type) {
		case map[string]any:
			value, ok := typed[part]
			if !ok {
				return nil, fmt.Errorf("%w: %q does not exist", errBootstrapReference, reference)
			}
			current = value
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("%w: %q does not exist", errBootstrapReference, reference)
			}
			current = typed[index]
		default:
			return nil, fmt.Errorf("%w: %q does not exist", errBootstrapReference, reference)
		}
	}
	if current == nil {
		return nil, fmt.Errorf("%w: %q resolved to null", errBootstrapReference, reference)
	}
	return current, nil
}

func decodeBootstrapObject(body []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var response map[string]any
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding object: %w", err)
	}
	if response == nil {
		return nil, fmt.Errorf("%w: API returned null", errBootstrapResponse)
	}
	return response, nil
}

func decodeBootstrapList(body []byte) ([]map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var response []map[string]any
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding list: %w", err)
	}
	if response == nil {
		response = []map[string]any{}
	}
	return response, nil
}

func bootstrapResponseID(response map[string]any) (string, error) {
	id, ok := response["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("%w: response does not contain a non-empty string id", errBootstrapResponse)
	}
	return id, nil
}

func isBootstrapNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
