// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"strings"
	"time"

	cauth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/config"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// DefaultIssuerReloadInterval is the cadence at which every replica rebuilds the
// DB-sourced portion of the live auth registry (the eventual-consistency floor).
const DefaultIssuerReloadInterval = 30 * time.Second

// IsStaticIssuer reports whether the given issuer URL (the token "iss") or name is
// owned by a static ConfigMap issuer. Static issuers always win: a DB issuer that
// collides is rejected at write time and skipped at load time.
func (c *Config) IsStaticIssuer(issuerURL, name string) bool {
	for _, ic := range c.GetIssuersConfig() {
		if ic.Issuer == issuerURL {
			return true
		}
		if name != "" && ic.Name == name {
			return true
		}
	}
	return false
}

// HasPrivilegedStaticIssuerOrigins reports whether any ConfigMap issuer uses a
// privileged origin (keycloak, kas-legacy, or kas-ssa). Runtime custom issuers may
// only be added when the static set is custom-only or empty — privileged IdPs own
// claim extraction and must not share the trust plane with API-managed issuers.
func (c *Config) HasPrivilegedStaticIssuerOrigins() bool {
	for _, ic := range c.GetIssuersConfig() {
		origin, err := ic.GetOrigin()
		if err != nil {
			continue
		}
		switch origin {
		case cauth.TokenOriginKeycloak, cauth.TokenOriginKasLegacy, cauth.TokenOriginKasSsa:
			return true
		}
	}
	return false
}

// HasDynamicConfigMapIssuers reports whether any ConfigMap issuer carries
// attribute-driven claim mappings (orgAttribute, orgDisplayAttribute, or
// rolesAttribute). The issuer API only coexists with fully static ConfigMap
// issuers; a dynamic ConfigMap issuer disables the API.
func (c *Config) HasDynamicConfigMapIssuers() bool {
	for _, ic := range c.GetIssuersConfig() {
		for _, cm := range ic.ClaimMappings {
			if cm.OrgAttribute != "" || cm.OrgDisplayAttribute != "" || cm.RolesAttribute != "" {
				return true
			}
		}
	}
	return false
}

// NewConfigFromYAML builds a Config from an in-memory YAML document. Used by
// tests that need a controlled issuers/keycloak block without loading an on-disk
// config.yaml.
func NewConfigFromYAML(yamlDoc string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetDefault(ConfigKeycloakEnabled, false)
	if err := v.ReadConfig(strings.NewReader(yamlDoc)); err != nil {
		return nil, err
	}
	return &Config{
		v:      v,
		dbURLs: map[string]bool{},
		dbSigs: map[string]string{},
	}, nil
}

// ValidateCombinedIssuers validates a candidate DB issuer against the full
// combined set of static ConfigMap issuers plus all other DB issuers, reusing the
// exact rules in ValidateIssuersConfig. excludeID, if set, drops that existing DB
// row (used on update so the row does not conflict with itself). candidate may be
// nil when validating the remaining set before a delete.
func (c *Config) ValidateCombinedIssuers(ctx context.Context, dbSession *cdb.Session, tx *cdb.Tx, candidate *cdbm.Issuer, excludeID *uuid.UUID) error {
	dao := cdbm.NewIssuerDAO(dbSession)
	existing, err := dao.GetAll(ctx, tx, cdbm.IssuerFilterInput{})
	if err != nil {
		return err
	}

	combined := append([]IssuerConfig{}, c.GetIssuersConfig()...)
	for _, di := range existing {
		if excludeID != nil && di.ID == *excludeID {
			continue
		}
		combined = append(combined, issuerConfigFromDB(di))
	}
	if candidate != nil {
		combined = append(combined, issuerConfigFromDB(*candidate))
	}

	return c.ValidateIssuersConfig(combined)
}

// StartIssuerReloadLoop starts a background ticker that periodically calls
// ReloadDBIssuers. This is the eventual-consistency floor across replicas: a write
// on one replica converges everywhere within one interval.
func (c *Config) StartIssuerReloadLoop(ctx context.Context, dbSession *cdb.Session, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultIssuerReloadInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.ReloadDBIssuers(ctx, dbSession); err != nil {
					log.Warn().Err(err).Msg("periodic DB issuer reload failed")
				}
			}
		}
	}()
}

// ReloadDBIssuers idempotently rebuilds the DB-sourced portion of the live
// registry. On the first call c.dbSigs is empty so every row is built; on
// subsequent calls only changed/new issuers are rebuilt and deleted ones are
// removed, preserving cached JWKS keys for unchanged issuers. Static ConfigMap
// issuers are never touched.
func (c *Config) ReloadDBIssuers(ctx context.Context, dbSession *cdb.Session) error {
	reg := c.JwtOriginConfig
	if reg == nil {
		return nil
	}

	c.dbMu.Lock()
	defer c.dbMu.Unlock()

	dbIssuers, err := cdbm.NewIssuerDAO(dbSession).GetAll(ctx, nil, cdbm.IssuerFilterInput{})
	if err != nil {
		return err
	}

	prevManaged := c.dbURLs

	// Accept DB issuers that (a) do not collide with a static/built-in issuer and
	// (b) keep the combined issuer set valid. One bad row never blocks the others.
	// DB issuers with a dynamic org mapping (orgAttribute) are always rejected here —
	// dynamic mappings are a cross-tenant escalation risk and must live in the ConfigMap.
	acceptedConfigs := append([]IssuerConfig{}, c.GetIssuersConfig()...)
	acceptedDB := make([]cdbm.Issuer, 0, len(dbIssuers))
	for _, di := range dbIssuers {
		if c.IsStaticIssuer(di.IssuerURL, di.Name) ||
			(c.JwtOriginConfig.GetConfig(di.IssuerURL) != nil && !prevManaged[di.IssuerURL]) {
			log.Warn().Str("issuer", di.IssuerURL).Str("name", di.Name).
				Msg("DB issuer conflicts with a static/built-in issuer; skipping (static wins)")
			continue
		}
		if di.HasDynamicMapping() {
			log.Warn().Str("issuer", di.IssuerURL).Str("name", di.Name).
				Msg("DB issuer has a dynamic org mapping (orgAttribute); skipping — dynamic issuers must be defined in the ConfigMap")
			continue
		}
		trial := append(append([]IssuerConfig{}, acceptedConfigs...), issuerConfigFromDB(di))
		if verr := c.ValidateIssuersConfig(trial); verr != nil {
			log.Warn().Err(verr).Str("issuer", di.IssuerURL).
				Msg("DB issuer failed validation against the current issuer set; skipping")
			continue
		}
		acceptedConfigs = trial
		acceptedDB = append(acceptedDB, di)
	}

	newManaged := make(map[string]bool, len(acceptedDB))
	newSigs := make(map[string]string, len(acceptedDB))
	for _, di := range acceptedDB {
		sig := di.Signature()
		newManaged[di.IssuerURL] = true
		newSigs[di.IssuerURL] = sig

		// Unchanged issuer already live — keep it and its cached JWKS keys.
		if c.dbSigs[di.IssuerURL] == sig && reg.GetConfig(di.IssuerURL) != nil {
			continue
		}

		jwksCfg := buildJwksConfig(di)
		if uerr := jwksCfg.UpdateJWKS(); uerr != nil {
			log.Warn().Err(uerr).Str("issuer", di.IssuerURL).
				Msg("failed to fetch JWKS for DB issuer; will retry lazily on first token")
		}
		reg.AddJwksConfig(jwksCfg)
	}

	// Remove DB-managed configs that are no longer present.
	// Static/Keycloak entries are never in prevManaged so they are never removed.
	for url := range prevManaged {
		if !newManaged[url] {
			reg.RemoveConfig(url)
		}
	}

	c.dbURLs = newManaged
	c.dbSigs = newSigs
	return nil
}

// issuerConfigFromDB projects a DB Issuer onto the ConfigMap IssuerConfig shape so
// the existing validator and registry-building logic can be reused unchanged.
func issuerConfigFromDB(di cdbm.Issuer) IssuerConfig {
	return IssuerConfig{
		Name:                         di.Name,
		Origin:                       di.Origin,
		JWKS:                         di.JWKSUrl,
		Issuer:                       di.IssuerURL,
		ServiceAccount:               di.ServiceAccount,
		Audiences:                    di.Audiences,
		Scopes:                       di.Scopes,
		JWKSTimeout:                  di.JWKSTimeout,
		ClaimMappings: convertClaimMappings(di.ClaimMappings),
	}
}

// convertClaimMappings maps the persisted claim mappings onto the in-memory auth
// claim mappings, lowercasing static org names to match the normalization applied
// to ConfigMap issuers.
func convertClaimMappings(in []cdbm.ClaimMapping) []cauth.ClaimMapping {
	out := make([]cauth.ClaimMapping, len(in))
	for i, cm := range in {
		out[i] = cauth.ClaimMapping{
			OrgAttribute:        cm.OrgAttribute,
			OrgDisplayAttribute: cm.OrgDisplayAttribute,
			OrgName:             cm.OrgName,
			OrgDisplayName:      cm.OrgDisplayName,
			RolesAttribute:      cm.RolesAttribute,
			Roles:               cm.Roles,
			Audiences:           cm.Audiences,
			IsServiceAccount:    cm.IsServiceAccount,
		}
		if out[i].OrgName != "" {
			out[i].OrgName = strings.ToLower(out[i].OrgName)
		}
	}
	return out
}

// computeReservedOrgNames collects the lowercased static org names across the
// combined issuer set (mirrors GetOrInitJWTOriginConfig's first pass).
func computeReservedOrgNames(configs []IssuerConfig) map[string]bool {
	reserved := map[string]bool{}
	for _, ic := range configs {
		for _, cm := range ic.ClaimMappings {
			if cm.OrgName != "" {
				reserved[strings.ToLower(cm.OrgName)] = true
			}
		}
	}
	return reserved
}

// buildJwksConfig builds a live JwksConfig for a DB issuer. DB issuers are always
// static-org (orgAttribute rows are filtered before this is called), so no
// reserved-org-names set is needed.
func buildJwksConfig(di cdbm.Issuer) *cauth.JwksConfig {
	origin := di.Origin
	if origin == "" {
		origin = cauth.TokenOriginCustom
	}
	cfg := cauth.NewJwksConfig(di.Name, di.JWKSUrl, di.IssuerURL, origin, di.ServiceAccount, di.Audiences, di.Scopes)
	if d, err := time.ParseDuration(di.JWKSTimeout); err == nil {
		cfg.JWKSTimeout = d
	}
	cfg.ClaimMappings = convertClaimMappings(di.ClaimMappings)
	return cfg
}

