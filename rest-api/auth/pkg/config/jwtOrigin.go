// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"sync"
	"time"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

// TokenOrigin constants define the source of JWT tokens
// These string values correspond to what's configured in the issuer configmap
const (
	TokenOriginKasLegacy = "kas-legacy" // Legacy KAS tokens
	TokenOriginKasSsa    = "kas-ssa"    // KAS SSA tokens
	TokenOriginKeycloak  = "keycloak"   // Keycloak tokens
	TokenOriginCustom    = "custom"     // Custom/third-party tokens (default if not specified)
)

// AllowedOrigins is the list of valid token origins for the service
var AllowedOrigins = []string{TokenOriginKasLegacy, TokenOriginKasSsa, TokenOriginKeycloak, TokenOriginCustom}

// TokenProcessor interface for processing JWT tokens
type TokenProcessor interface {
	ProcessToken(c echo.Context, tokenStr string, jwksConfig *JwksConfig, logger zerolog.Logger) (*cdbm.User, *util.APIError)
}

const (
	// unknownIssuerTTL is how long an issuer the resolver could not find is
	// remembered as absent, so tokens naming a nonexistent issuer cost one query per
	// window rather than one per request.
	unknownIssuerTTL = 5 * time.Second

	// maxUnknownIssuers bounds the unknown-issuer cache. On overflow it is dropped
	// wholesale, since it is only an optimization.
	maxUnknownIssuers = 256

	// DefaultResolveFlightTimeout is the ceiling for one shared resolution when
	// auth.resolveFlightTimeout is unset. It must outlive any single waiter, so the
	// first caller to hang up cannot cancel the lookup the others are waiting on.
	DefaultResolveFlightTimeout = 30 * time.Second
)

// IssuerResolver looks up an issuer that is not in the registry, returning nil
// without an error when no such issuer exists. The api layer installs one backed by
// the issuer table.
//
// A resolver that returns a config must also publish it with AddJwksConfig before
// returning. Publication is the resolver's job because only it can hold the same
// lock the delete path takes, without which a resolution racing a deletion would
// re-add withdrawn trust.
type IssuerResolver func(ctx context.Context, issuerURL string) (*JwksConfig, error)

// JWTOriginConfig holds configuration for JWT origins with multiple JWKS configs and handlers
type JWTOriginConfig struct {
	sync.RWMutex                           // protects concurrent access to configs and handlers maps
	configs      map[string]*JwksConfig    // map issuer -> JWKSConfig
	processors   map[string]TokenProcessor // map TokenOrigin -> TokenProcessor

	resolver       IssuerResolver
	resolveGroup   singleflight.Group
	unknownIssuers map[string]time.Time
	resolveTimeout time.Duration
}

// NewJWTOriginConfig initializes and returns a configuration object with empty maps
func NewJWTOriginConfig() *JWTOriginConfig {
	return &JWTOriginConfig{
		configs:        make(map[string]*JwksConfig),
		processors:     make(map[string]TokenProcessor),
		resolveTimeout: DefaultResolveFlightTimeout,
	}
}

// SetResolveFlightTimeout sets the ceiling for one on-demand issuer resolution.
// Zero or negative falls back to DefaultResolveFlightTimeout.
func (jc *JWTOriginConfig) SetResolveFlightTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultResolveFlightTimeout
	}
	jc.Lock()
	jc.resolveTimeout = d
	jc.Unlock()
}

func (jc *JWTOriginConfig) resolveFlightTimeout() time.Duration {
	jc.RLock()
	d := jc.resolveTimeout
	jc.RUnlock()
	if d <= 0 {
		return DefaultResolveFlightTimeout
	}
	return d
}

// SetIssuerResolver installs the resolve-on-miss backend. Passing nil disables
// resolution, which is the default and what Keycloak mode uses.
func (jc *JWTOriginConfig) SetIssuerResolver(r IssuerResolver) {
	jc.Lock()
	defer jc.Unlock()
	jc.resolver = r
}

// ResolveConfig returns the JWKS configuration for an issuer, falling back to the
// installed resolver when the registry does not have it yet, so a replica learns
// about a new issuer from the periodic reload or the first token naming it,
// whichever comes first.
//
// Concurrent misses for the same issuer collapse into one resolver call. It runs on
// its own bounded context so no single waiter's cancellation can abort it, while
// each waiter still returns as soon as its own ctx is done.
func (jc *JWTOriginConfig) ResolveConfig(ctx context.Context, issuer string) *JwksConfig {
	if cfg := jc.GetConfig(issuer); cfg != nil {
		return cfg
	}

	jc.RLock()
	resolver := jc.resolver
	expiry, known := jc.unknownIssuers[issuer]
	jc.RUnlock()

	if resolver == nil || (known && time.Now().Before(expiry)) {
		return nil
	}

	ch := jc.resolveGroup.DoChan(issuer, func() (any, error) {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jc.resolveFlightTimeout())
		defer cancel()

		// A concurrent reload may have installed it while this call was queued.
		if cfg := jc.GetConfig(issuer); cfg != nil {
			return cfg, nil
		}
		return resolver(resolveCtx, issuer)
	})

	var res singleflight.Result
	select {
	case <-ctx.Done():
		return nil
	case res = <-ch:
	}

	if res.Err != nil {
		log.Warn().Err(res.Err).Str("issuer", issuer).Msg("failed to resolve issuer on demand")
		return nil
	}

	if cfg, _ := res.Val.(*JwksConfig); cfg == nil {
		jc.rememberUnknownIssuer(issuer)
		return nil
	}

	// The resolver publishes under the lock that orders it against a concurrent
	// withdrawal, so reading the registry back is how this call learns which won: an
	// issuer deleted mid-resolution is absent here and must not be served.
	published := jc.GetConfig(issuer)
	if published == nil {
		jc.rememberUnknownIssuer(issuer)
	}
	return published
}

// rememberUnknownIssuer records an issuer the resolver reported as nonexistent.
func (jc *JWTOriginConfig) rememberUnknownIssuer(issuer string) {
	jc.Lock()
	defer jc.Unlock()

	if jc.unknownIssuers == nil || len(jc.unknownIssuers) >= maxUnknownIssuers {
		jc.unknownIssuers = make(map[string]time.Time, 1)
	}
	jc.unknownIssuers[issuer] = time.Now().Add(unknownIssuerTTL)
}

// AddJwksConfig adds a pre-configured JwksConfig for an issuer
// This is the preferred method for adding configurations
func (jc *JWTOriginConfig) AddJwksConfig(cfg *JwksConfig) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[cfg.Issuer] = cfg
}

// AddConfig adds a new JWKS config with the specified issuer, URL, origin, and serviceAccount flag
func (jc *JWTOriginConfig) AddConfig(issuer, url string, origin string, serviceAccount bool, audiences []string, scopes []string) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[issuer] = NewJwksConfig(url, issuer, origin, serviceAccount, audiences, scopes)
}

// AddConfigWithProcessor adds a new JWKS config and processor for the specified origin
func (jc *JWTOriginConfig) AddConfigWithProcessor(issuer, url string, origin string, serviceAccount bool, audiences []string, scopes []string, processor TokenProcessor) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[issuer] = NewJwksConfig(url, issuer, origin, serviceAccount, audiences, scopes)
	jc.processors[origin] = processor
}

// SetProcessorForOrigin sets a processor for the specified token origin
func (jc *JWTOriginConfig) SetProcessorForOrigin(origin string, processor TokenProcessor) {
	jc.Lock()
	defer jc.Unlock()
	jc.processors[origin] = processor
}

// GetProcessorByOrigin returns the processor for the specified origin
func (jc *JWTOriginConfig) GetProcessorByOrigin(origin string) TokenProcessor {
	jc.RLock()
	defer jc.RUnlock()
	return jc.processors[origin]
}

// GetProcessorByIssuer finds a processor that exactly matches the given issuer
func (jc *JWTOriginConfig) GetProcessorByIssuer(issuer string) TokenProcessor {
	jc.RLock()
	defer jc.RUnlock()
	config := jc.configs[issuer]
	if config != nil {
		return jc.processors[config.Origin]
	}
	return nil
}

// GetConfig returns the JWKS configuration for the specified issuer
func (jc *JWTOriginConfig) GetConfig(issuer string) *JwksConfig {
	jc.RLock()
	defer jc.RUnlock()
	return jc.configs[issuer]
}

// GetConfigsByOrigin returns all JWKS configurations for the specified origin
func (jc *JWTOriginConfig) GetConfigsByOrigin(origin string) map[string]*JwksConfig {
	jc.RLock()
	defer jc.RUnlock()
	result := make(map[string]*JwksConfig)
	for issuer, config := range jc.configs {
		if config.Origin == origin {
			result[issuer] = config
		}
	}
	return result
}

// GetFirstConfigByOrigin returns the first JWKS configuration with the specified origin
func (jc *JWTOriginConfig) GetFirstConfigByOrigin(origin string) *JwksConfig {
	jc.RLock()
	defer jc.RUnlock()
	for _, config := range jc.configs {
		if config.Origin == origin {
			return config
		}
	}
	return nil
}

// RemoveConfig removes the JWKS configuration for the specified issuer
func (jc *JWTOriginConfig) RemoveConfig(issuer string) {
	jc.Lock()
	defer jc.Unlock()
	delete(jc.configs, issuer)
}

// GetAllConfigs returns all JWKS configurations
func (jc *JWTOriginConfig) GetAllConfigs() map[string]*JwksConfig {
	jc.RLock()
	defer jc.RUnlock()
	return jc.configs
}

// UpdateAllJWKS updates the JWKs for all configurations in the map
// Updates are performed in parallel for better performance with multiple issuers.
// Continues on individual failures - only returns error if ALL updates fail.
func (jc *JWTOriginConfig) UpdateAllJWKS() error {
	// Collect configs under lock, then release before network I/O
	jc.RLock()
	jwksConfigs := make([]*JwksConfig, 0, len(jc.configs))
	for _, config := range jc.configs {
		if config != nil && config.URL != "" {
			jwksConfigs = append(jwksConfigs, config)
		}
	}
	jc.RUnlock()

	if len(jwksConfigs) == 0 {
		return nil
	}

	// Update all configs in parallel
	var wg sync.WaitGroup
	errChan := make(chan error, len(jwksConfigs))

	for _, jwksConfig := range jwksConfigs {
		wg.Add(1)
		go func(innerJwksConfig *JwksConfig) {
			defer wg.Done()
			if err := innerJwksConfig.UpdateJWKS(); err != nil {
				log.Warn().Err(err).Str("issuer", innerJwksConfig.Issuer).Msg("Failed to update JWKS")
				errChan <- err
			}
		}(jwksConfig)
	}

	wg.Wait()
	close(errChan)

	// Collect errors - panic if ALL updates failed (at least 1 must work)
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) == len(jwksConfigs) {
		log.Panic().Msgf("all JWKS updates failed (%d issuers) - at least one issuer must be reachable at startup", len(errs))
	}

	if len(errs) > 0 {
		log.Warn().Int("failed", len(errs)).Int("total", len(jwksConfigs)).Int("succeeded", len(jwksConfigs)-len(errs)).
			Msg("Some JWKS updates failed, continuing with available issuers")
	}

	return nil
}

// GetKeycloakProcessor returns the processor for Keycloak tokens
func (jc *JWTOriginConfig) GetKeycloakProcessor() TokenProcessor {
	jc.RLock()
	defer jc.RUnlock()
	return jc.processors[TokenOriginKeycloak]
}

// GetSsaProcessor returns the processor for SSA tokens
func (jc *JWTOriginConfig) GetSsaProcessor() TokenProcessor {
	jc.RLock()
	defer jc.RUnlock()
	return jc.processors[TokenOriginKasSsa]
}

// GetKasProcessor returns the processor for KAS tokens
func (jc *JWTOriginConfig) GetKasProcessor() TokenProcessor {
	jc.RLock()
	defer jc.RUnlock()
	return jc.processors[TokenOriginKasLegacy]
}

// SetProcessors sets all processors at once for easier initialization
func (jc *JWTOriginConfig) SetProcessors(keycloakProcessor, ssaProcessor, kasProcessor TokenProcessor) {
	jc.Lock()
	defer jc.Unlock()
	jc.processors[TokenOriginKeycloak] = keycloakProcessor
	jc.processors[TokenOriginKasSsa] = ssaProcessor
	jc.processors[TokenOriginKasLegacy] = kasProcessor
}

// IsServiceAccount checks if the given issuer supports service account tokens
func (jc *JWTOriginConfig) IsServiceAccount(issuer string) bool {
	jc.RLock()
	defer jc.RUnlock()
	config := jc.configs[issuer]
	if config != nil {
		return config.ServiceAccount
	}
	return false
}
