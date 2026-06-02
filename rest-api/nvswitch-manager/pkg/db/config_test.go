// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"github.com/NVIDIA/infra-controller-rest/common/pkg/credential"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigValidate(t *testing.T) {
	sharedCredential := credential.New("admin", "password")

	tests := map[string]struct {
		config  Config
		wantErr bool
	}{
		"valid config": {
			config: Config{
				Host:       "localhost",
				Port:       5432,
				DBName:     "testdb",
				Credential: sharedCredential,
			},
			wantErr: false,
		},
		"missing host": {
			config: Config{
				Port:       5432,
				DBName:     "testdb",
				Credential: sharedCredential,
			},
			wantErr: true,
		},
		"invalid port (zero)": {
			config: Config{
				Host:       "localhost",
				Port:       0,
				DBName:     "testdb",
				Credential: sharedCredential,
			},
			wantErr: true,
		},
		"missing database name": {
			config: Config{
				Host:       "localhost",
				Port:       5432,
				Credential: sharedCredential,
			},
			wantErr: true,
		},
		"invalid credential": {
			config: Config{
				Host:   "localhost",
				Port:   5432,
				DBName: "testdb",
				Credential: credential.Credential{
					Password: sharedCredential.Password,
				},
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigBuildDSN(t *testing.T) {
	sharedCredential := credential.New("user", "password")

	tests := map[string]struct {
		config   Config
		expected string
	}{
		"with CA certificate": {
			config: Config{
				Host:              "localhost",
				Port:              5432,
				DBName:            "testdb",
				Credential:        sharedCredential,
				CACertificatePath: "/path/to/ca.crt",
			},
			expected: "postgres://user:password@localhost:5432/testdb?sslmode=prefer&sslrootcert=/path/to/ca.crt",
		},
		"without CA certificate": {
			config: Config{
				Host:       "localhost",
				Port:       5432,
				DBName:     "testdb",
				Credential: sharedCredential,
			},
			expected: "postgres://user:password@localhost:5432/testdb?sslmode=disable",
		},
		"special characters in password": {
			config: Config{
				Host:       "localhost",
				Port:       5432,
				DBName:     "testdb",
				Credential: credential.New("admin", "p@ss:word/1"),
			},
			expected: "postgres://admin:p%40ss%3Aword%2F1@localhost:5432/testdb?sslmode=disable",
		},
		"special characters in user and password": {
			config: Config{
				Host:       "db.example.com",
				Port:       5433,
				DBName:     "mydb",
				Credential: credential.New("user@domain", "s3cr3t#!"),
			},
			expected: "postgres://user%40domain:s3cr3t%23%21@db.example.com:5433/mydb?sslmode=disable",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dsn := tt.config.BuildDSN()
			assert.Equal(t, tt.expected, dsn)
		})
	}
}
