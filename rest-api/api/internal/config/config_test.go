// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type logContainsWriter struct {
	needle string
	seen   chan struct{}
}

func (w logContainsWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.needle) {
		select {
		case w.seen <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func writeConfigForTest(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name string
		want *Config
	}{
		{
			name: "initialize config",
			want: &Config{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewConfig()

			defaultPath := ProjectRoot + "/config.yaml"

			assert.Equal(t, defaultPath, got.GetPathToConfig())
		})
	}
}

func TestGetIssuersConfigClaimMappingAudiences(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(`
issuers:
  - issuer: https://auth.example.com
    jwks: https://auth.example.com/.well-known/jwks.json
    origin: custom
    audiences: [issuer-audience]
    claimMappings:
      - orgName: acme
        roles: [TENANT_ADMIN]
        audiences: [org-audience]
`)))

	c := &Config{v: v}
	issuers := c.GetIssuersConfig()
	require.Len(t, issuers, 1)
	require.Len(t, issuers[0].ClaimMappings, 1)
	assert.Equal(t, []string{"issuer-audience"}, issuers[0].Audiences)
	assert.Equal(t, []string{"org-audience"}, issuers[0].ClaimMappings[0].Audiences)
}

// TestValidateIssuersConfigIdentityUniqueness covers the uniqueness rule shared by
// the ConfigMap, the create path, reload, and the on-demand resolver: no two
// issuers may claim the same issuer URL or JWKS URL. Each is reported as an
// identity conflict so callers can answer 409 instead of 400.
func TestValidateIssuersConfigIdentityUniqueness(t *testing.T) {
	issuer := func(issuerURL, jwksURL, orgName string) IssuerConfig {
		return IssuerConfig{
			Origin:        "custom",
			Issuer:        issuerURL,
			JWKS:          jwksURL,
			ClaimMappings: []cauth.ClaimMapping{{OrgName: orgName, Roles: []string{"TENANT_ADMIN"}}},
		}
	}
	first := issuer("https://first.example.com", "https://first.example.com/jwks", "first-org")

	tests := []struct {
		name        string
		second      IssuerConfig
		wantErrPart string
	}{
		{
			name:   "distinct_identities",
			second: issuer("https://second.example.com", "https://second.example.com/jwks", "second-org"),
		},
		{
			name:        "duplicate_issuer_url",
			second:      issuer("https://first.example.com", "https://second.example.com/jwks", "second-org"),
			wantErrPart: "duplicate issuer URL",
		},
		{
			name:        "duplicate_jwks_url",
			second:      issuer("https://second.example.com", "https://first.example.com/jwks", "second-org"),
			wantErrPart: "duplicate JWKS URL",
		},
	}

	c := &Config{v: viper.New()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.ValidateIssuersConfig([]IssuerConfig{first, tt.second})

			if tt.wantErrPart == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrPart)
			assert.ErrorIs(t, err, ErrIssuerIdentityConflict, "callers map this to 409, not 400")
		})
	}
}

// TestValidateIssuersConfigSharedStaticOrgs covers who may own a static org name.
// By default one issuer owns it; auth.sharedStaticOrgs lets several static mappings
// name the same org with different issuers or roles. The allowance is deliberately
// narrow: it never covers a second mapping inside one issuer, and never a second
// service account for the org.
func TestValidateIssuersConfigSharedStaticOrgs(t *testing.T) {
	issuer := func(host string, mappings ...cauth.ClaimMapping) IssuerConfig {
		return IssuerConfig{
			Origin:        "custom",
			Issuer:        "https://" + host + ".example.com",
			JWKS:          "https://" + host + ".example.com/jwks",
			ClaimMappings: mappings,
		}
	}
	tenantAdmin := cauth.ClaimMapping{OrgName: "Acme", Roles: []string{"TENANT_ADMIN"}}
	providerAdmin := cauth.ClaimMapping{OrgName: "acme", Roles: []string{"PROVIDER_ADMIN"}}
	serviceAccount := cauth.ClaimMapping{OrgName: "acme", IsServiceAccount: true}

	tests := []struct {
		name         string
		shared       bool
		disconnected bool
		issuers      []IssuerConfig
		wantErrPart  string
	}{
		{
			name:        "distinct_orgs_need_no_sharing",
			issuers:     []IssuerConfig{issuer("first", tenantAdmin), issuer("second", cauth.ClaimMapping{OrgName: "beta", Roles: []string{"TENANT_ADMIN"}})},
			wantErrPart: "",
		},
		{
			name:        "shared_org_rejected_by_default",
			issuers:     []IssuerConfig{issuer("first", tenantAdmin), issuer("second", providerAdmin)},
			wantErrPart: "must be unique across all issuers",
		},
		{
			name:    "shared_org_allowed_when_enabled",
			shared:  true,
			issuers: []IssuerConfig{issuer("first", tenantAdmin), issuer("second", providerAdmin)},
		},
		{
			name:        "sharing_does_not_permit_two_mappings_in_one_issuer",
			shared:      true,
			issuers:     []IssuerConfig{issuer("first", tenantAdmin, providerAdmin)},
			wantErrPart: "an issuer may map an org at most once",
		},
		{
			name:         "sharing_does_not_permit_a_second_service_account",
			shared:       true,
			disconnected: true,
			issuers:      []IssuerConfig{issuer("first", serviceAccount), issuer("second", serviceAccount)},
			wantErrPart:  "already has a service account mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{v: viper.New()}
			c.SetAuthSharedStaticOrgs(tt.shared)
			c.v.Set(ConfigEnvDisconnected, tt.disconnected)

			err := c.ValidateIssuersConfig(tt.issuers)

			if tt.wantErrPart == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrPart)
		})
	}

	// A shared org name is still statically owned, so dynamic mappings stay locked out.
	reserved := computeReservedOrgNames([]IssuerConfig{issuer("first", tenantAdmin), issuer("second", providerAdmin)})
	assert.True(t, reserved["acme"], "sharing an org name does not release the reservation")
}

// TestValidateIssuersConfigJWKSTimeout covers the bound on how long one issuer's
// IdP may hold a token-path request. Parsing alone was not enough: a zero or
// negative duration silently reverted to the default, and an arbitrarily large
// one made the timeout meaningless.
func TestValidateIssuersConfigJWKSTimeout(t *testing.T) {
	tests := []struct {
		name        string
		timeout     string
		wantErrPart string
	}{
		{name: "unset_uses_the_default", timeout: ""},
		{name: "typical", timeout: "5s"},
		{name: "at_the_maximum", timeout: MaxJWKSTimeout.String()},
		{name: "unparseable", timeout: "soon", wantErrPart: "invalid jwksTimeout"},
		{name: "zero", timeout: "0s", wantErrPart: "must be positive"},
		{name: "negative", timeout: "-5s", wantErrPart: "must be positive"},
		{name: "above_the_maximum", timeout: (MaxJWKSTimeout + time.Second).String(), wantErrPart: "must not exceed"},
	}

	c := &Config{v: viper.New()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.ValidateIssuersConfig([]IssuerConfig{{
				Origin:        "custom",
				Issuer:        "https://idp.acme.com",
				JWKS:          "https://idp.acme.com/jwks",
				JWKSTimeout:   tt.timeout,
				ClaimMappings: []cauth.ClaimMapping{{OrgName: "acme", Roles: []string{"TENANT_ADMIN"}}},
			}})

			if tt.wantErrPart == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrPart)
		})
	}
}

func TestConfig_WatchConfigFile(t *testing.T) {
	const initialSitePhoneHomeURL = "http://initial.example/phone_home"

	tests := []struct {
		name string // description of this test case
		run  func(t *testing.T, c *Config, configPath string)
	}{
		{
			name: "keeps current site phone home URL when changed config cannot be read",
			run: func(t *testing.T, c *Config, configPath string) {
				seenConfigChange := make(chan struct{}, 1)
				previousLogger := log.Logger
				log.Logger = zerolog.New(logContainsWriter{
					needle: "config file changed",
					seen:   seenConfigChange,
				})
				t.Cleanup(func() {
					log.Logger = previousLogger
				})

				require.NoError(t, os.WriteFile(configPath, []byte("site:\n  phoneHomeUrl: [\n"), 0o600))

				require.Eventually(t, func() bool {
					select {
					case <-seenConfigChange:
						return true
					default:
						return false
					}
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, initialSitePhoneHomeURL, c.GetSitePhoneHomeUrl())
			},
		},
		{
			name: "reloads site phone home URL from changed config",
			run: func(t *testing.T, c *Config, configPath string) {
				const updatedSitePhoneHomeURL = "http://updated.example/phone_home"

				require.NoError(t, os.WriteFile(configPath, []byte(`
log:
  level: debug
site:
  phoneHomeUrl: http://updated.example/phone_home
`), 0o600))

				require.Eventually(t, func() bool {
					return c.GetSitePhoneHomeUrl() == updatedSitePhoneHomeURL
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, "info", c.v.GetString(ConfigLogLevel))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: http://initial.example/phone_home
`)
			c := &Config{v: viper.New()}
			c.v.SetDefault(ConfigFilePath, configPath)
			c.v.SetConfigFile(configPath)
			c.v.SetDefault(ConfigLogLevel, "info")
			c.SetSitePhoneHomeUrl(initialSitePhoneHomeURL)
			c.WatchConfigFile()
			tt.run(t, c, configPath)
		})
	}
}
