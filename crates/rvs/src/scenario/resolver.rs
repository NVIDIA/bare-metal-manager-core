use jsonpath_rust::JsonPath;

use super::Scenario;
use crate::artifact::ArtifactDownload;
use crate::client::RackFirmwareData;
use crate::ctx::RvsCtx;
use crate::error::RvsError;

/// Resolve all artifact download URLs for all scenarios.
///
/// For each scenario collects:
///   - OS image (`scenario.os.uri`)
///   - Direct-URI artifacts (`artifact.uri`)
///   - SOT-resolved artifacts (`artifact.sotpath`) evaluated via JSONPath
///
/// The caller is responsible for providing the SOT JSON when sotpath
/// artifacts are present.
pub fn resolve_artifact_urls<'a>(
    sot: &'a RackFirmwareData,
    ctx: &'a RvsCtx,
) -> Result<Vec<ArtifactDownload<'a>>, RvsError> {
    let mut downloads = vec![];

    for scenario in &ctx.scenarios {
        downloads.extend(resolve_for_scenario(
            sot,
            scenario,
            &ctx.cfg.artifact_cache.cache_dir,
        )?);
    }

    Ok(downloads)
}

fn resolve_for_scenario<'a>(
    sot: &'a RackFirmwareData,
    scenario: &'a Scenario,
    cache_dir: &str,
) -> Result<Vec<ArtifactDownload<'a>>, RvsError> {
    let ns = format!("{}/{}", scenario.rack.model, scenario.rack.sot_release);
    let mut downloads = vec![];

    // OS image
    downloads.push(ArtifactDownload {
        output_path: format!("{cache_dir}/{ns}/os"),
        url: scenario.os.uri.as_str(),
    });

    // Direct-URI artifacts
    for (artifact, url) in scenario
        .artifacts
        .iter()
        .filter_map(|a| Some((a, a.uri.as_deref()?)))
    {
        downloads.push(ArtifactDownload {
            output_path: format!("{cache_dir}/{ns}/{}", artifact.output),
            url,
        });
    }

    // SOT-resolved artifacts
    for (artifact, sotpath) in scenario
        .artifacts
        .iter()
        .filter_map(|a| Some((a, a.sotpath.as_deref()?)))
    {
        let url = eval_sotpath(sot, sotpath)?;
        downloads.push(ArtifactDownload {
            output_path: format!("{cache_dir}/{ns}/{}", artifact.output),
            url,
        });
    }

    Ok(downloads)
}

/// Evaluate a JSONPath expression against the SOT config and return the
/// first matching string value (the download URL), borrowed from the SOT.
fn eval_sotpath<'a>(sot: &'a RackFirmwareData, sotpath: &str) -> Result<&'a str, RvsError> {
    let results = sot
        .config
        .query_with_path(sotpath)
        .map_err(|e| RvsError::InvalidArg(format!("invalid sotpath '{sotpath}': {e}")))?;

    let value = results
        .into_iter()
        .next()
        .ok_or_else(|| RvsError::InvalidArg(format!("sotpath '{sotpath}' matched nothing")))?;

    value.val().as_str().ok_or_else(|| {
        RvsError::InvalidArg(format!("sotpath '{sotpath}' did not resolve to a string"))
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn make_sot(config: serde_json::Value) -> RackFirmwareData {
        RackFirmwareData {
            id: "test".to_string(),
            config,
        }
    }

    fn make_scenario(model: &str, sot_release: &str) -> Scenario {
        Scenario {
            rack: super::super::RackTarget {
                model: model.to_string(),
                sot_release: sot_release.to_string(),
            },
            os: super::super::OsImage {
                uri: "https://example.com/os.img".to_string(),
            },
            artifacts: vec![],
            setup: vec![],
            test: vec![],
            teardown: vec![],
        }
    }

    // --- eval_sotpath ---

    #[test]
    fn eval_sotpath_returns_first_string_match() {
        let sot = make_sot(json!({ "firmware": { "url": "https://cdn.example.com/fw.bin" } }));
        let url = eval_sotpath(&sot, "$.firmware.url").unwrap();
        assert_eq!(url, "https://cdn.example.com/fw.bin");
    }

    #[test]
    fn eval_sotpath_no_match_is_error() {
        let sot = make_sot(json!({ "firmware": {} }));
        let err = eval_sotpath(&sot, "$.firmware.url").unwrap_err();
        assert!(err.to_string().contains("matched nothing"), "got: {err}");
    }

    #[test]
    fn eval_sotpath_non_string_match_is_error() {
        let sot = make_sot(json!({ "firmware": { "version": 42 } }));
        let err = eval_sotpath(&sot, "$.firmware.version").unwrap_err();
        assert!(
            err.to_string().contains("did not resolve to a string"),
            "got: {err}"
        );
    }

    // --- resolve_for_scenario ---

    #[test]
    fn resolve_for_scenario_os_image_only() {
        let sot = make_sot(json!({}));
        let scenario = make_scenario("gb200nvl", "1.2.5");
        let downloads = resolve_for_scenario(&sot, &scenario, "/cache").unwrap();
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].output_path, "/cache/gb200nvl/1.2.5/os");
        assert_eq!(downloads[0].url, "https://example.com/os.img");
    }

    #[test]
    fn resolve_for_scenario_direct_uri_artifact() {
        let sot = make_sot(json!({}));
        let mut scenario = make_scenario("gb200nvl", "1.2.5");
        scenario.artifacts.push(super::super::Artifact {
            name: "diag".to_string(),
            output: "diag.bin".parse().unwrap(),
            uri: Some("https://example.com/diag.bin".to_string()),
            sotpath: None,
        });
        let downloads = resolve_for_scenario(&sot, &scenario, "/cache").unwrap();
        assert_eq!(downloads.len(), 2);
        assert_eq!(downloads[1].output_path, "/cache/gb200nvl/1.2.5/diag.bin");
        assert_eq!(downloads[1].url, "https://example.com/diag.bin");
    }

    #[test]
    fn resolve_for_scenario_sotpath_artifact() {
        let sot = make_sot(json!({ "packages": { "diag": "https://cdn.example.com/diag.bin" } }));
        let mut scenario = make_scenario("gb200nvl", "1.2.5");
        scenario.artifacts.push(super::super::Artifact {
            name: "diag".to_string(),
            output: "diag.bin".parse().unwrap(),
            uri: None,
            sotpath: Some("$.packages.diag".to_string()),
        });
        let downloads = resolve_for_scenario(&sot, &scenario, "/cache").unwrap();
        assert_eq!(downloads.len(), 2);
        assert_eq!(downloads[1].output_path, "/cache/gb200nvl/1.2.5/diag.bin");
        assert_eq!(downloads[1].url, "https://cdn.example.com/diag.bin");
    }

    #[test]
    fn resolve_for_scenario_sotpath_missing_is_error() {
        let sot = make_sot(json!({}));
        let mut scenario = make_scenario("gb200nvl", "1.2.5");
        scenario.artifacts.push(super::super::Artifact {
            name: "diag".to_string(),
            output: "diag.bin".parse().unwrap(),
            uri: None,
            sotpath: Some("$.packages.diag".to_string()),
        });
        let err = resolve_for_scenario(&sot, &scenario, "/cache").unwrap_err();
        assert!(err.to_string().contains("matched nothing"), "got: {err}");
    }
}
