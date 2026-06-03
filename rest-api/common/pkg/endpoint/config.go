// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"errors"
	"fmt"

	"github.com/NVIDIA/infra-controller-rest/common/pkg/credential"
)

// Config represents a network endpoint with optional authentication and TLS.
type Config struct {
	Host              string
	Port              int
	Credential        *credential.Credential
	CACertificatePath string
}

// Validate checks if the Config fields are set correctly.
func (c *Config) Validate() error {
	if c.Host == "" {
		return errors.New("host is required")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("port must be between (0, 65535]")
	}

	if c.Credential != nil && !c.Credential.IsValid() {
		return errors.New("valid credential is required")
	}

	return nil
}

// Target returns the host:port connection string.
func (c *Config) Target() string {
	return fmt.Sprintf("%s:%v", c.Host, c.Port)
}
