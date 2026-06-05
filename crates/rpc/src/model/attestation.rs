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

/// Model for SPDM attestation via Redfish
pub mod spdm {

    use model::attestation::spdm::{SpdmAttestationStatus, SpdmDeviceAttestationDetails};

    use crate as rpc;

    impl From<SpdmDeviceAttestationDetails> for rpc::forge::SpdmAttestationDetails {
        fn from(value: SpdmDeviceAttestationDetails) -> Self {
            rpc::forge::SpdmAttestationDetails {
                machine_id: Some(value.machine_id),
                completed_at: value.completed_at.map(|x| x.into()),
                started_at: Some(value.started_at.into()),
                cancelled_at: value.cancelled_at.map(|x| x.into()),
                state: format!("{:?}", value.state),
                device_id: value.device_id,
            }
        }
    }

    impl From<SpdmAttestationStatus> for rpc::forge::SpdmAttestationStatus {
        fn from(value: SpdmAttestationStatus) -> Self {
            match value {
                SpdmAttestationStatus::InProgress => Self::SpdmAttInProgress,
                SpdmAttestationStatus::Cancelled => Self::SpdmAttCancelled,
                SpdmAttestationStatus::Passed => Self::SpdmAttPassed,
                SpdmAttestationStatus::Failed => Self::SpdmAttFailed,
            }
        }
    }
}
