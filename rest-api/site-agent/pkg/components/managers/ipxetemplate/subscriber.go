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

// RegisterSubscriber registers the IpxeTemplate workflows/activities with the Temporal client.
// IpxeTemplate is read-only (propagated from nico-core), so no CRUD workflows are registered.
func (api *API) RegisterSubscriber() error {
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: Registering the subscribers")
	ManagerAccess.Data.EB.Log.Info().Msg("IpxeTemplate: No CRUD workflows for IpxeTemplate (read-only resource)")
	return nil
}
