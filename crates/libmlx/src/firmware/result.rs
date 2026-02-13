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

use rpc::protos::mlx_device::FirmwareFlashReport as FirmwareFlashReportPb;
use serde::{Deserialize, Serialize};

// FirmwareFlashReport captures the outcome of each step in the
// firmware flash lifecycle. Built by scout after executing the
// ApplyFirmware operation and sent back to the API as part of an
// MlxObservation.
//
// Each optional step (reset, verify_image, verify_version) is
// controlled by the corresponding flag in FlashOptions.
// A None value means the step was not requested; Some(true/false)
// means it was attempted and the result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirmwareFlashReport {
    // Whether the firmware was successfully flashed via flint.
    pub flashed: bool,
    // Whether the device was successfully reset via mlxfwreset.
    // None if config.reset was false (not requested).
    pub reset: Option<bool>,
    // Whether the firmware image on the device was verified against
    // the source image via flint verify.
    // None if config.verify_image was false (not requested).
    pub verified_image: Option<bool>,
    // Whether the firmware version on the device matches the expected
    // version. None if config.verify_version was false (not requested).
    pub verified_version: Option<bool>,
    // The firmware version observed on the device after flashing,
    // queried via mlxfwmanager. None if the device could not be
    // queried or if the step was not performed.
    pub observed_version: Option<String>,
    // The expected firmware version from the config, if one was set.
    pub expected_version: Option<String>,
}

// From implementations for converting FirmwareFlashReport
// to/from a FirmwareFlashReportPb protobuf message and back.
impl From<FirmwareFlashReport> for FirmwareFlashReportPb {
    fn from(result: FirmwareFlashReport) -> Self {
        FirmwareFlashReportPb {
            flashed: result.flashed,
            reset: result.reset,
            verified_image: result.verified_image,
            verified_version: result.verified_version,
            observed_version: result.observed_version,
            expected_version: result.expected_version,
        }
    }
}

impl From<FirmwareFlashReportPb> for FirmwareFlashReport {
    fn from(proto: FirmwareFlashReportPb) -> Self {
        FirmwareFlashReport {
            flashed: proto.flashed,
            reset: proto.reset,
            verified_image: proto.verified_image,
            verified_version: proto.verified_version,
            observed_version: proto.observed_version,
            expected_version: proto.expected_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flasher_result_all_steps_success() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: Some(true),
            verified_image: Some(true),
            verified_version: Some(true),
            observed_version: Some("32.43.1014".to_string()),
            expected_version: Some("32.43.1014".to_string()),
        };
        let proto: FirmwareFlashReportPb = original.clone().into();
        let converted: FirmwareFlashReport = proto.into();

        assert_eq!(original.flashed, converted.flashed);
        assert_eq!(original.reset, converted.reset);
        assert_eq!(original.verified_image, converted.verified_image);
        assert_eq!(original.verified_version, converted.verified_version);
        assert_eq!(original.observed_version, converted.observed_version);
        assert_eq!(original.expected_version, converted.expected_version);
    }

    #[test]
    fn test_flasher_result_flash_only() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: None,
            verified_image: None,
            verified_version: None,
            observed_version: None,
            expected_version: None,
        };
        let proto: FirmwareFlashReportPb = original.clone().into();
        let converted: FirmwareFlashReport = proto.into();

        assert!(converted.flashed);
        assert!(converted.reset.is_none());
        assert!(converted.verified_image.is_none());
        assert!(converted.verified_version.is_none());
        assert!(converted.observed_version.is_none());
    }

    #[test]
    fn test_flasher_result_partial_failure() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: Some(false),
            verified_image: Some(false),
            verified_version: Some(false),
            observed_version: Some("32.42.900".to_string()),
            expected_version: Some("32.43.1014".to_string()),
        };
        let proto: FirmwareFlashReportPb = original.clone().into();
        let converted: FirmwareFlashReport = proto.into();

        assert!(converted.flashed);
        assert_eq!(converted.reset, Some(false));
        assert_eq!(converted.verified_image, Some(false));
        assert_eq!(converted.verified_version, Some(false));
    }

    #[test]
    fn test_flasher_result_default() {
        let report = FirmwareFlashReport::default();
        assert!(!report.flashed);
        assert!(report.reset.is_none());
        assert!(report.verified_image.is_none());
        assert!(report.verified_version.is_none());
        assert!(report.observed_version.is_none());
        assert!(report.expected_version.is_none());
    }
}
