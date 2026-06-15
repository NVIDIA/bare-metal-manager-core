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

package ipxetemplate

import "fmt"

// Init initializes the IpxeTemplate manager
func (api *API) Init() {
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: Initializing IpxeTemplate API")
}

// GetState returns the current state of the IpxeTemplate manager
func (api *API) GetState() []string {
	state := ManagerAccess.Data.EB.Managers.Workflow.IpxeTemplateState
	var strs []string
	strs = append(strs, fmt.Sprintln("ipxe_template_workflow_started", state.WflowStarted.Load()))
	strs = append(strs, fmt.Sprintln("ipxe_template_workflow_activity_failed", state.WflowActFail.Load()))
	strs = append(strs, fmt.Sprintln("ipxe_template_workflow_activity_succeeded", state.WflowActSucc.Load()))
	strs = append(strs, fmt.Sprintln("ipxe_template_workflow_publishing_failed", state.WflowPubFail.Load()))
	strs = append(strs, fmt.Sprintln("ipxe_template_workflow_publishing_succeeded", state.WflowPubSucc.Load()))
	return strs
}
