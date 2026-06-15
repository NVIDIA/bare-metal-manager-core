/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package model

import (
	"time"

	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

// APIIpxeTemplate is the data structure to capture the API representation of an iPXE template.
//
// iPXE templates are global in REST and identified by the stable UUID assigned by core
// (`ID`). Per-site availability is tracked separately and not surfaced in this payload.
type APIIpxeTemplate struct {
	// ID is the stable template UUID assigned by core, identical between core and REST
	ID string `json:"id"`
	// Name is the globally unique template name (e.g. "ubuntu-autoinstall", "kernel-initrd")
	Name string `json:"name"`
	// Template is the raw iPXE script content
	Template string `json:"template"`
	// RequiredParams lists the parameters that must be provided to render the template
	RequiredParams []string `json:"requiredParams"`
	// ReservedParams lists the parameters that are reserved by the template and cannot be user-supplied
	ReservedParams []string `json:"reservedParams"`
	// RequiredArtifacts lists the artifact names (e.g. "kernel", "initrd") required for the template
	RequiredArtifacts []string `json:"requiredArtifacts"`
	// Scope indicates the visibility of this template: "Internal" or "Public"
	Scope string `json:"scope"`
	// Created is the date and time the entity was created in this system
	Created time.Time `json:"created"`
	// Updated is the date and time the entity was last updated in this system
	Updated time.Time `json:"updated"`
}

// NewAPIIpxeTemplate accepts a DB layer IpxeTemplate object and returns an API layer object
func NewAPIIpxeTemplate(dbTemplate *cdbm.IpxeTemplate) *APIIpxeTemplate {
	if dbTemplate == nil {
		return nil
	}

	requiredParams := dbTemplate.RequiredParams
	if requiredParams == nil {
		requiredParams = []string{}
	}

	reservedParams := dbTemplate.ReservedParams
	if reservedParams == nil {
		reservedParams = []string{}
	}

	requiredArtifacts := dbTemplate.RequiredArtifacts
	if requiredArtifacts == nil {
		requiredArtifacts = []string{}
	}

	return &APIIpxeTemplate{
		ID:                dbTemplate.ID.String(),
		Name:              dbTemplate.Name,
		Template:          dbTemplate.Template,
		RequiredParams:    requiredParams,
		ReservedParams:    reservedParams,
		RequiredArtifacts: requiredArtifacts,
		Scope:             dbTemplate.Scope,
		Created:           dbTemplate.Created,
		Updated:           dbTemplate.Updated,
	}
}
