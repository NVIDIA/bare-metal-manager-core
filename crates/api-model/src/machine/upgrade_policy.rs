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

use std::cmp::Ordering;
use std::fmt;

use crate::firmware::AgentUpgradePolicyChoice;

/// How we decide whether a DPU should upgrade its forge-dpu-agent
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AgentUpgradePolicy {
    /// Never upgrade it
    Off,
    /// Upgrade but never downgrade. Allows us to test new versions manually.
    UpOnly,
    /// Upgrade or downgrade as necessary to make the versions match
    UpDown,
}

impl fmt::Display for AgentUpgradePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // enums are a special case where their debug impl is their name ("Off")
        fmt::Debug::fmt(self, f)
    }
}

impl AgentUpgradePolicy {
    // The versions are strings like this: v2023.09-rc1-27-gc3ce4d5d
    pub fn should_upgrade(&self, agent_version: &str, carbide_api_version: &str) -> bool {
        use AgentUpgradePolicy::*;
        match self {
            Off => false,
            UpOnly => {
                let agent = match BuildVersion::try_from(agent_version) {
                    Ok(bv) => bv,
                    Err(err) => {
                        tracing::error!(
                            invalid_version = agent_version,
                            error = format!("{err:#}"),
                            "Invalid agent build version. Forcing upgrade."
                        );
                        // If the agent has an invalid build version we need to fix it,
                        // otherwise upgrades would be broken forever.
                        return true;
                    }
                };
                let carbide = match BuildVersion::try_from(carbide_api_version) {
                    Ok(bv) => bv,
                    Err(err) => {
                        tracing::error!(
                            invalid_version = carbide_api_version,
                            error = format!("{err:#}"),
                            "Invalid carbide-api build version"
                        );
                        // If carbide has an invalid version we wait until a fixed
                        // carbide is deployed.
                        return false;
                    }
                };
                agent.cmp(&carbide).is_lt()
            }
            UpDown => agent_version != carbide_api_version,
        }
    }
}

// From the database
impl From<&str> for AgentUpgradePolicy {
    fn from(str_policy: &str) -> Self {
        match str_policy {
            "Off" | "off" => AgentUpgradePolicy::Off,
            "UpOnly" | "uponly" | "up_only" => AgentUpgradePolicy::UpOnly,
            "UpDown" | "updown" | "up_down" => AgentUpgradePolicy::UpDown,
            _ => {
                tracing::error!(
                    invalid_policy = str_policy,
                    "Invalid dpu agent upgrade policy name in database. Disabling upgrades."
                );
                AgentUpgradePolicy::Off
            }
        }
    }
}

// From the RPC
impl From<i32> for AgentUpgradePolicy {
    fn from(rpc_policy: i32) -> Self {
        use rpc::forge::AgentUpgradePolicy::*;
        match rpc_policy {
            n if n == Off as i32 => AgentUpgradePolicy::Off,
            n if n == UpOnly as i32 => AgentUpgradePolicy::UpOnly,
            n if n == UpDown as i32 => AgentUpgradePolicy::UpDown,
            _ => {
                unreachable!();
            }
        }
    }
}

// To the RPC
impl From<AgentUpgradePolicy> for i32 {
    fn from(p: AgentUpgradePolicy) -> Self {
        use AgentUpgradePolicy::*;
        match p {
            Off => rpc::forge::AgentUpgradePolicy::Off as i32,
            UpOnly => rpc::forge::AgentUpgradePolicy::UpOnly as i32,
            UpDown => rpc::forge::AgentUpgradePolicy::UpDown as i32,
        }
    }
}

// From the config file
impl From<AgentUpgradePolicyChoice> for AgentUpgradePolicy {
    fn from(c: AgentUpgradePolicyChoice) -> Self {
        use crate::firmware::AgentUpgradePolicyChoice::*;
        match c {
            Off => AgentUpgradePolicy::Off,
            UpOnly => AgentUpgradePolicy::UpOnly,
            UpDown => AgentUpgradePolicy::UpDown,
        }
    }
}

/// Represents a build version, supporting both date-based (v2023.08) and semver (v0.0.4) formats.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildVersion<'a> {
    /// The main version part. Either a date (2023.08) or semver (0.0.4)
    version: &'a str,
    rc: &'a str,
    hotfix: usize,
    commits: usize,
    git_hash: &'a str,
}

impl BuildVersion<'_> {
    /// Returns true if this is a date-based version (starts with "20")
    fn is_date_version(&self) -> bool {
        self.version.starts_with("20")
    }

    /// Parse semver "X.Y.Z" into (major, minor, patch) for comparison
    fn parse_semver(&self) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = self.version.split('.').collect();
        if parts.len() >= 3
            && let (Ok(major), Ok(minor), Ok(patch)) = (
                parts[0].parse::<u32>(),
                parts[1].parse::<u32>(),
                parts[2].parse::<u32>(),
            )
        {
            return Some((major, minor, patch));
        }
        None
    }
}

impl fmt::Display for BuildVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "v{}", self.version)?;
        if !self.rc.is_empty() {
            // rc and hotfix must either both appear, or neither
            write!(f, "-{}-{}", self.rc, self.hotfix)?;
        }
        if self.commits != 0 {
            write!(f, "-{}", self.commits)?;
        }
        if !self.git_hash.is_empty() {
            write!(f, "-{}", self.git_hash)?;
        }
        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for BuildVersion<'a> {
    type Error = eyre::Report;

    fn try_from(s: &'_ str) -> Result<BuildVersion<'_>, Self::Error> {
        if s.is_empty() {
            eyre::bail!("Build version is empty");
        }
        if !s.starts_with('v') {
            eyre::bail!("Build version should start with a 'v'");
        }
        let parts = s[1..].split('-').collect::<Vec<&str>>();
        if parts.is_empty() || parts[0].is_empty() {
            eyre::bail!("Build version should have a version number after 'v'");
        }
        // Validate that the first part looks like a version (date or semver)
        // Date: 2023.08, 2024.05.02
        // Semver: 0.0.4, 1.2.3
        let first_char = parts[0].chars().next().unwrap();
        if !first_char.is_ascii_digit() {
            eyre::bail!("Build version should start with a digit after 'v'");
        }
        match parts.len() {
            // Tag only. The tag is <year>.<month> or semver. e.g:
            // v2023.08 or v0.0.4
            1 => Ok(BuildVersion {
                version: parts[0],
                rc: "",
                hotfix: 0,
                commits: 0,
                git_hash: "",
            }),
            // Tag only with a release-candidate part
            // v2023.09-rc1 or v0.0.4-rc1
            2 => Ok(BuildVersion {
                version: parts[0],
                rc: parts[1],
                hotfix: 0,
                commits: 0,
                git_hash: "",
            }),
            // Version tag with commits OR new style version-rc-hotfix
            // v2023.08-92-g1b48e8b6 OR v2024.05.02-rc3-0
            3 => {
                if parts[1].chars().next().unwrap().is_numeric() {
                    // v2023.08-92-g1b48e8b6
                    Ok(BuildVersion {
                        version: parts[0],
                        rc: "",
                        hotfix: 0,
                        commits: parts[1].parse().unwrap(),
                        git_hash: parts[2],
                    })
                } else {
                    // v2024.05.02-rc3-0 or v0.0.4-rc4-0
                    Ok(BuildVersion {
                        version: parts[0],
                        rc: parts[1],
                        hotfix: parts[2].parse().unwrap(),
                        commits: 0,
                        git_hash: "",
                    })
                }
            }
            // Version-and-rc tag, commits
            // v2023.09-rc1-27-gc3ce4d5d or v0.0.4-rc4-0-g2a3c98cac
            4 => Ok(BuildVersion {
                version: parts[0],
                rc: parts[1],
                hotfix: 0,
                commits: parts[2].parse().unwrap(),
                git_hash: parts[3],
            }),
            // version, rc, hotfix, commits and hash
            // v2024.05.02-rc4-0-27-gc3ce4d5d or v0.0.4-rc4-0-27-gc3ce4d5d
            5 => Ok(BuildVersion {
                version: parts[0],
                rc: parts[1],
                hotfix: parts[2].parse().unwrap(),
                commits: parts[3].parse().unwrap(),
                git_hash: parts[4],
            }),
            n => {
                eyre::bail!("Invalid build version. Has {n} dash-separated parts.")
            }
        }
    }
}

impl Ord for BuildVersion<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // If one is date-based and one is semver, semver is always newer
        // (represents migration from date-based to semver versioning)
        match (self.is_date_version(), other.is_date_version()) {
            (true, false) => return Ordering::Less,    // date < semver
            (false, true) => return Ordering::Greater, // semver > date
            (false, false) => {
                // Both are semver - compare numerically
                if let (Some(self_ver), Some(other_ver)) =
                    (self.parse_semver(), other.parse_semver())
                {
                    return self_ver
                        .cmp(&other_ver)
                        .then_with(|| self.rc.cmp(other.rc))
                        .then_with(|| self.hotfix.cmp(&other.hotfix))
                        .then_with(|| self.commits.cmp(&other.commits));
                }
                // Fall through to string comparison if parse fails
            }
            (true, true) => {
                // Both are date-based - use existing string comparison
            }
        }
        // Default: string comparison (works for date-based versions)
        self.version
            .cmp(other.version)
            .then_with(|| self.rc.cmp(other.rc))
            .then_with(|| self.hotfix.cmp(&other.hotfix))
            .then_with(|| self.commits.cmp(&other.commits))
    }
}

impl PartialOrd for BuildVersion<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
fn test_parse_version() -> eyre::Result<()> {
    // Date-based versions
    assert_eq!(
        BuildVersion::try_from("v2023.08-92-g1b48e8b6")?,
        BuildVersion {
            version: "2023.08",
            rc: "",
            hotfix: 0,
            commits: 92,
            git_hash: "g1b48e8b6",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v2023.09-rc1-27-gc3ce4d5d")?,
        BuildVersion {
            version: "2023.09",
            rc: "rc1",
            hotfix: 0,
            commits: 27,
            git_hash: "gc3ce4d5d",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v2023.08")?,
        BuildVersion {
            version: "2023.08",
            rc: "",
            hotfix: 0,
            commits: 0,
            git_hash: "",
        }
    );

    // Semver versions
    assert_eq!(
        BuildVersion::try_from("v0.0.4-rc4-0-g2a3c98cac")?,
        BuildVersion {
            version: "0.0.4",
            rc: "rc4",
            hotfix: 0,
            commits: 0,
            git_hash: "g2a3c98cac",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v1.2.3")?,
        BuildVersion {
            version: "1.2.3",
            rc: "",
            hotfix: 0,
            commits: 0,
            git_hash: "",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v0.0.4-rc1-0")?,
        BuildVersion {
            version: "0.0.4",
            rc: "rc1",
            hotfix: 0,
            commits: 0,
            git_hash: "",
        }
    );

    // Too many dashes
    assert!(BuildVersion::try_from("v2023.08-rc1-0-3-g123eff-x").is_err());

    // No version
    assert!(BuildVersion::try_from("v-rc1").is_err());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::BuildVersion;

    #[test]
    fn test_compare_versions() -> eyre::Result<()> {
        use rand::prelude::SliceRandom;

        // In the correct order
        const VERSIONS: &[(&str, Option<&str>)] = &[
            // Left is input, Right is output if different
            // Due to Debian version numbering contraints, we changed the rules in May 2024 to
            // force a "hotfix" number to appear if and only if the rc number appears.
            //
            // Date-based versions (older)
            ("v2023.04", None),
            ("v2023.04.01", None),
            ("v2023.04.01-1-g17e5c956", None),
            (
                "v2023.06-rc2-1-gc5c05de3",
                Some("v2023.06-rc2-0-1-gc5c05de3"),
            ),
            ("v2023.08", None),
            ("v2023.08-14-gbc549a66", None),
            ("v2023.08-89-gd73315bc", None),
            ("v2023.08-92-g1b48e8b6", None),
            ("v2023.09-89-gd73315bc", None),
            ("v2023.09-rc1", Some("v2023.09-rc1-0")),
            (
                "v2023.09-rc1-1-g681e499f",
                Some("v2023.09-rc1-0-1-g681e499f"),
            ),
            (
                "v2023.09-rc1-27-gc3ce4d5d",
                Some("v2023.09-rc1-0-27-gc3ce4d5d"),
            ),
            ("v2024.05-rc3-0", None),
            ("v2024.05.02-rc3-0", None),
            ("v2024.05.02-rc4-0-27-gc3ce4d5d", None),
            ("v2024.05.10-rc1-0-3-g6497fef4d", None),
            ("v2024.05.10-rc1-3", None),
            // Semver versions (newer than all date-based versions)
            ("v0.0.1", None),
            ("v0.0.4-rc1-0", None),
            ("v0.0.4-rc4-0-g2a3c98cac", None),
            ("v0.0.5", None),
            ("v1.0.0", None),
            ("v1.2.3-rc1-0", None),
        ];
        let mut rng = rand::rng();

        // What we're testing
        let mut t: Vec<BuildVersion> = VERSIONS.iter().map(|v| (v.0).try_into().unwrap()).collect();
        t.shuffle(&mut rng);
        t.sort();

        // 't' should now be in the original order again
        for (i, (expect_normal, expect_different)) in VERSIONS.iter().enumerate() {
            let got = t[i].to_string();
            let expect = expect_different.unwrap_or(expect_normal);
            if got != expect {
                panic!("Pos {i} does not match. Got {got} expected {expect}.");
            }
        }

        Ok(())
    }

    #[test]
    fn test_semver_comparison() -> eyre::Result<()> {
        let v0_0_1 = BuildVersion::try_from("v0.0.1")?;
        let v0_0_4 = BuildVersion::try_from("v0.0.4-rc4-0-g2a3c98cac")?;
        let v1_0_0 = BuildVersion::try_from("v1.0.0")?;
        let v_date = BuildVersion::try_from("v2024.05.10-rc1-3")?;

        // Semver ordering
        assert!(v0_0_1 < v0_0_4);
        assert!(v0_0_4 < v1_0_0);

        // Semver is always newer than date-based
        assert!(v_date < v0_0_1);

        Ok(())
    }
}
