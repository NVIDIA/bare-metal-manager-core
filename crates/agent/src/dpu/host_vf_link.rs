use std::collections::{HashMap, HashSet};
use std::path::Path;

use eyre::WrapErr;

mod parse_hbn_conf;

#[derive(Debug, Eq, PartialEq)]
/// Maps tenant VF IDs to their HBN-owned host representors.
struct VfInterfaceMap {
    representor_names: HashMap<u32, String>,
}

impl VfInterfaceMap {
    /// Loads a validated host VF ownership mapping from an HBN configuration file.
    async fn load_from(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let path = path.as_ref();
        let contents = tokio::fs::read_to_string(path)
            .await
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        Self::parse(&contents).wrap_err_with(|| format!("parsing {}", path.display()))
    }

    /// Parses host VF ownership entries from an HBN configuration file.
    ///
    /// An example minimal valid configuration is:
    ///
    /// ```text
    /// [LINK_PROPAGATION]
    /// pf0vf7:pf0vf7_if_r
    /// ```
    fn parse(contents: &str) -> eyre::Result<Self> {
        Ok(Self {
            representor_names: parse_hbn_conf::get_hbn_vf_mapping(contents)?,
        })
    }

    /// Returns the names of every host VF representor owned by this mapping.
    fn managed_host_representors(&self) -> impl Iterator<Item = &str> + '_ {
        self.representor_names.values().map(String::as_str)
    }

    /// Returns the owned host representor associated with a VF ID.
    fn representor_name(&self, vf_id: u32) -> Option<&str> {
        self.representor_names.get(&vf_id).map(String::as_str)
    }

    /// Returns the set of VF IDs accepted by this ownership mapping.
    fn valid_vf_ids(&self) -> HashSet<u32> {
        self.representor_names.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vf_map(entries: &[(u32, &str)]) -> VfInterfaceMap {
        VfInterfaceMap {
            representor_names: entries
                .iter()
                .map(|(vf_id, interface)| (*vf_id, (*interface).to_string()))
                .collect(),
        }
    }

    #[test]
    fn retains_configured_host_representor_names() {
        let interface_map = vf_map(&[(7, "pf0vf07"), (1, "pf0vf1")]);
        let mut representors = interface_map
            .managed_host_representors()
            .collect::<Vec<_>>();
        representors.sort();

        assert_eq!(representors, ["pf0vf07", "pf0vf1"]);
    }
}
