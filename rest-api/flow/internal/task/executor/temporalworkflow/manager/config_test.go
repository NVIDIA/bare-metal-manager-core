// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/worker"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/endpoint"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/clients/temporal"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/secret"
)

func TestConfigValidateRequiresDataCipher(t *testing.T) {
	conf := Config{
		ClientConf: temporal.Config{
			Endpoint: endpoint.Config{Host: "temporal", Port: 7233},
		},
		WorkerOptions: map[string]worker.Options{
			WorkflowQueue: {},
		},
	}

	err := conf.Validate()

	require.EqualError(t, err, "data encryption cipher is required")
}

func TestConfigValidateAcceptsDataCipher(t *testing.T) {
	key := make([]byte, 32)
	cipher, err := secret.NewCipher(base64.StdEncoding.EncodeToString(key))
	require.NoError(t, err)
	conf := Config{
		ClientConf: temporal.Config{
			Endpoint: endpoint.Config{Host: "temporal", Port: 7233},
		},
		WorkerOptions: map[string]worker.Options{
			WorkflowQueue: {},
		},
		DataCipher: cipher,
	}

	require.NoError(t, conf.Validate())
}
