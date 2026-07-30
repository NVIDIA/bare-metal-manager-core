// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"
	"fmt"
)

// DataStoreType selects credential store backend.
type DataStoreType string

const (
	DatastoreTypeCore     DataStoreType = "Core"
	DatastoreTypeInMemory DataStoreType = "InMemory"
)

// Config holds the selected backend and provider config (NICo Core).
type Config struct {
	DataStoreType DataStoreType
	CoreConfig    *CoreConfig
}

func (c *Config) String() string {
	return fmt.Sprintf("DataStoreType: %s; CoreConfig: %v", c.DataStoreType, c.CoreConfig)
}

// Validate checks if the Config fields are set correctly.
func (c *Config) Validate() error {
	switch c.DataStoreType {
	case DatastoreTypeCore:
		if c.CoreConfig == nil {
			return errors.New("core config needs to be specified when using NICo Core as the credential manager datastore")
		}

		return c.CoreConfig.Validate()
	}
	return nil
}
