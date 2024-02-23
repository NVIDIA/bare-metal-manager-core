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

use std::cmp::Ordering;
use std::fmt;

/// How we decide whether a DPU should upgrade it's forge-dpu-agent
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
impl From<crate::cfg::AgentUpgradePolicyChoice> for AgentUpgradePolicy {
    fn from(c: crate::cfg::AgentUpgradePolicyChoice) -> Self {
        use crate::cfg::AgentUpgradePolicyChoice::*;
        match c {
            Off => AgentUpgradePolicy::Off,
            UpOnly => AgentUpgradePolicy::UpOnly,
            UpDown => AgentUpgradePolicy::UpDown,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BuildVersion<'a> {
    date: &'a str,
    rc: &'a str,
    commits: usize,
    git_hash: &'a str,
}

impl fmt::Display for BuildVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "v{}", self.date)?;
        if !self.rc.is_empty() {
            write!(f, "-{}", self.rc)?;
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

    fn try_from(s: &str) -> Result<BuildVersion, Self::Error> {
        let parts = s[1..].split('-').collect::<Vec<&str>>();
        if parts.is_empty() || !parts[0].starts_with("20") {
            eyre::bail!("Build version should have at least a date");
        }
        match parts.len() {
            // Tag only. The tag is <year>.<month>[-rc<num>]. e.g:
            // v2023.08
            1 => Ok(BuildVersion {
                date: parts[0],
                rc: "",
                commits: 0,
                git_hash: "",
            }),
            // Tag only with a release-candidate part
            // v2023.09-rc1
            2 => Ok(BuildVersion {
                date: parts[0],
                rc: parts[1],
                commits: 0,
                git_hash: "",
            }),
            // Date-only tag, commits
            // v2023.08-92-g1b48e8b6
            3 => Ok(BuildVersion {
                date: parts[0],
                rc: "",
                commits: parts[1].parse().unwrap(),
                git_hash: parts[2],
            }),
            // Date-and-rc tag, commits
            // v2023.09-rc1-27-gc3ce4d5d
            4 => Ok(BuildVersion {
                date: parts[0],
                rc: parts[1],
                commits: parts[2].parse().unwrap(),
                git_hash: parts[3],
            }),
            n => {
                eyre::bail!("Invalid build version. Has {n} dashes, max 3")
            }
        }
    }
}

impl Ord for BuildVersion<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.date
            .cmp(other.date)
            .then(self.rc.cmp(other.rc))
            .then(self.commits.cmp(&other.commits))
    }
}

impl PartialOrd for BuildVersion<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
fn test_parse_version() -> eyre::Result<()> {
    assert_eq!(
        BuildVersion::try_from("v2023.08-92-g1b48e8b6")?,
        BuildVersion {
            date: "2023.08",
            rc: "",
            commits: 92,
            git_hash: "g1b48e8b6",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v2023.09-rc1-27-gc3ce4d5d")?,
        BuildVersion {
            date: "2023.09",
            rc: "rc1",
            commits: 27,
            git_hash: "gc3ce4d5d",
        }
    );

    assert_eq!(
        BuildVersion::try_from("v2023.08")?,
        BuildVersion {
            date: "2023.08",
            rc: "",
            commits: 0,
            git_hash: "",
        }
    );

    // Too many dashes
    assert!(BuildVersion::try_from("v2023.08-1-2-3-45").is_err());

    // No date
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
        const VERSIONS: &[&str] = &[
            "v2023.04",
            "v2023.04.01",
            "v2023.04.01-1-g17e5c956",
            "v2023.06-rc2-1-gc5c05de3",
            "v2023.08",
            "v2023.08-14-gbc549a66",
            "v2023.08-89-gd73315bc",
            "v2023.08-92-g1b48e8b6",
            "v2023.09-89-gd73315bc",
            "v2023.09-rc1",
            "v2023.09-rc1-1-g681e499f",
            "v2023.09-rc1-27-gc3ce4d5d",
        ];
        let mut rng = rand::thread_rng();

        // What we're testing
        let mut t: Vec<BuildVersion> = VERSIONS.iter().map(|v| (*v).try_into().unwrap()).collect();
        t.shuffle(&mut rng);
        t.sort();

        // 't' should now be in the original order again
        for (i, expect) in VERSIONS.iter().enumerate() {
            let got = t[i].to_string();
            if &got != expect {
                panic!("Pos {i} does not match. Got {got} expected {expect}.");
            }
        }

        Ok(())
    }
}
