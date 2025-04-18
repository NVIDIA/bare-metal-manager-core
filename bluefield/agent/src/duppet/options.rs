/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/// SummaryFormat allows the caller to configure how they
/// want a summary reported at the end of of the run.
#[derive(Debug)]
pub enum SummaryFormat {
    PlainText,
    Json,
    Yaml,
}

/// SyncOptions allows the caller to control various
/// aspects of the duppet sync.
#[derive(Debug)]
pub struct SyncOptions {
    /// dry_run allows the caller to perform a dry run
    /// on the sync -- no files will be created or updated,
    /// and it will simply log and report what would have
    /// been done.
    pub dry_run: bool,
    /// quiet will make it so duppet doesn't log individual
    /// file updates, and will leave it until the end when
    /// a summary is printed.
    pub quiet: bool,
    /// no_color will exclude the beautiful colors that
    /// are included in messages, if that's what you really
    /// want.
    pub no_color: bool,
    /// summary_format is the format of the report summary
    /// at the end of the run (plaintext, json, yaml).
    pub summary_format: SummaryFormat,
}

/// FileSpec defines a file specification for the
/// desired state of the file being created, including
/// the content, the permissions, the owner, and the
/// group.
#[derive(Debug, Clone)]
pub struct FileSpec {
    /// content is the actual file content to set.
    pub content: String,
    /// permissions are the optional permissions to
    /// set on the file. If None, no permission management
    /// will happen, and system defaults will be used, and
    /// no attempts to keep permissions in sync will occur.
    pub permissions: Option<u32>,
    /// owner is an optional owner to set for the file. If
    /// None, then no owner management will happen, and
    /// the system default will be used, and no attempts
    /// to keep the owner in sync will occur.
    pub owner: Option<String>,
    /// group is an optional group to set for the file. If None,
    /// then no group management will happen, and the system
    /// default will be used, and no attempts to keep the group
    /// in sync will occur.
    pub group: Option<String>,
}

impl FileSpec {
    /// new_with_content is a small helper to create a new FileSpec
    /// with some content, with explicit permissions of 0o644, but
    /// no owner/group management.
    pub fn new_with_content(content: impl Into<String>) -> Self {
        FileSpec {
            content: content.into(),
            permissions: Some(0o644),
            owner: None,
            group: None,
        }
    }

    /// new_with_perms is a small helper to create a new FileSpec
    /// with some content and explicit permissions, but no owner
    /// or group management.
    pub fn new_with_perms(content: impl Into<String>, permissions: u32) -> Self {
        FileSpec {
            content: content.into(),
            permissions: Some(permissions),
            owner: None,
            group: None,
        }
    }
}
