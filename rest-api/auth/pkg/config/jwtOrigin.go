// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"sync"

	"github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

// JWTOriginConfig holds configuration for JWT origins with multiple JWKS configs and handlers
type JWTOriginConfig struct {
	sync.RWMutex                           // protects concurrent access to configs and handlers maps
	configs      map[string]*JwksConfig    // map issuer -> JWKSConfig
	processors   map[string]TokenProcessor // map TokenOrigin -> TokenProcessor
}

// NewJWTOriginConfig initializes and returns a configuration object with empty maps
func NewJWTOriginConfig() *JWTOriginConfig {
	return &JWTOriginConfig{
		configs:    make(map[string]*JwksConfig),
		processors: make(map[string]TokenProcessor),
	}
}

// AddJwksConfig adds a pre-configured JwksConfig for an issuer
// This is the preferred method for adding configurations
func (jc *JWTOriginConfig) AddJwksConfig(cfg *JwksConfig) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[cfg.Issuer] = cfg
}

// AddConfig adds a new JWKS config with the specified name, issuer, URL, origin, and serviceAccount flag
func (jc *JWTOriginConfig) AddConfig(name, issuer, url string, origin string, serviceAccount bool, audiences []string, scopes []string) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[issuer] = NewJwksConfig(name, url, issuer, origin, serviceAccount, audiences, scopes)
}

// AddConfigWithProcessor adds a new JWKS config and processor for the specified origin
func (jc *JWTOriginConfig) AddConfigWithProcessor(name, issuer, url string, origin string, serviceAccount bool, audiences []string, scopes []string, processor TokenProcessor) {
	jc.Lock()
	defer jc.Unlock()
	jc.configs[issuer] = NewJwksConfig(name, url, issuer, origin, serviceAccount, audiences, scopes)
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
