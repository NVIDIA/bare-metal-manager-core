// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package bootstraptypes

import (
	"go.uber.org/atomic"
	coreV1Types "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Tags must match those in SecretConfig
const (
	TagUUID     = "site-uuid"
	TagOTP      = "otp"
	TagCredsURL = "creds-url"
	TagCACert   = "cacert"
)

// SecretConfig Secret file contents of the data section
type SecretConfig struct {
	UUID     string `yaml:"site-uuid"`
	OTP      string `yaml:"otp"`
	CredsURL string `yaml:"creds-url"`
	CACert   string `yaml:"cacert"`
}

// SecretReq Secret request data body
type SecretReq struct {
	UUID string `json:"siteuuid"`
	OTP  string `json:"otp"`
}

// SiteCredsResponse defines a site credentials response
type SiteCredsResponse struct {
	// Key is the private key
	Key string `json:"key,omitempty"`
	// Certificate is the client certificate
	Certificate string `json:"certificate,omitempty"`
	// CACertificate is the CA cert for validating the server
	CACertificate string `json:"cacertificate,omitempty"`
}

// State - state of the bootstrap process
type State struct {
	// DownloadSucceeded the Credentials file has been updated
	DownloadSucceeded atomic.Uint64
	// DownloadAttempted the number of times the secret file has been updated
	DownloadAttempted atomic.Uint64
}

// Bootstrap - data type for Bootstrap
type Bootstrap struct {
	Config      *SecretConfig
	State       *State
	Secret      coreV1Types.SecretInterface
	Secretfiles map[string]bool
}

// NewBootstrapInstance - creates a new instance of Bootstrap
func NewBootstrapInstance() *Bootstrap {
	return &Bootstrap{
		Config:      &SecretConfig{},
		State:       &State{},
		Secretfiles: make(map[string]bool),
	}
}
