#!/usr/bin/env python3
"""Generate the GB200 NVSWITCH telemetry source matrix.

The source workbook is not tracked. Pass sanitized catalog extraction artifacts with
``--rows-csv`` and ``--coverage-json`` when regenerating review artifacts.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = ROOT / "docs/architecture/health"
DEFAULT_OUT_CSV = DEFAULT_OUT_DIR / "nvswitch_telemetry_gb200_matrix.csv"
DEFAULT_OUT_MD = DEFAULT_OUT_DIR / "nvswitch_telemetry_gb200_matrix.md"

GB200_COLUMNS = [
    "Applicable for \nGB200 NVL HMC",
    "Applicable for \nGB200 NVL BMC",
    "Applicable for\nGB200 NVL NvswitchTray",
]

COL_METRIC = "Metric (ParamName)"
COL_GUID = "Telemetry GUID (Device+ParamName)"
COL_DEVICE = "Device \n(CompClass)"
COL_CATEGORY = "Category\n(ParamClass)"
COL_DATA_TYPE = "Data\nType"
COL_DESC = "Description"
COL_AVAIL = "Availability\n(IB/OOB/BOTH/NONE)"
COL_WILDCARD = "OOB API - Wildcards\n(Redfish URI and Field. N/A for NvSwitch Tray)"
COL_URI_DOMAIN = "URI Search Domain"
COL_URI_MATCH = "URI Match Criteria for Search Domain"
COL_OTLP = "OTLP"
COL_ONBOARD = "Onboard API (dbus path etc. within HMC/BMC)"
COL_NMXT = "Hi @zhillel@nvidia.com, IIUC these interfaces will be applicable even if there is single or no compute node at all correct in the rack ? so no need to say its \"applicable for multi node\" ?\n_Assigned to Ziv Hillel IL_\n-Pradeep Kumar Shima US\nNMX-T(applicable for MultiNode)"
COL_GNMI = "NVOS gNMI(applicable for MultiNode)"
COL_CLI_2502 = "Format of this column:\nline-1: nvos cli command with any placeholder for Id starting with \"$\"\nline-2 (Optional): Search criteria/filter for finding the applicable IDs for the placeholder in column. If this line isn't present, we'll look at all available Ids (interfaces, fans etc.)\nline-3: Property to check enclosed in curly braces. For example, {voltage}. For nested properties, curly braces can be used. E.g. {link{counters}}\n-Afsana Chowdhury US\nNVOS CLI v25.02.4282 (applicable for MultiNode)"
COL_CLI_2503 = "NVOS CLI v25.03.XXXX (applicable for MultiNode)"
COL_REDFISH_GB = "OOB API on GH200 NVL/GB200 NVL/GB300 NVL/MGX-4U-NVL16/Vera Rubin NVL72\n(Redfish URI and Field. N/A for NvSwitch Tray)"
COL_REDFISH_DGX = "Candidate to get rid of\n-Afsana Chowdhury US\nCheck with Jim and Joe about partners' usage\n-Afsana Chowdhury US\nOOB API on GH200/C2/DGX Station GB300\n(Redfish URI and Field. N/A for NvSwitch Tray)"
COL_MRD = "MRD URI on Hopper-HGX-8-GPU/Blackwell-HGX-8-GPU/GH200/GB200/HGX B300 NVL8/GB300/MGX-4U-NVL16\n(N/A for NvSwitch Tray)"

SOURCE_COLUMNS = {
    "redfish_gb": COL_REDFISH_GB,
    "redfish_dgx_or_c2": COL_REDFISH_DGX,
    "redfish_wildcard": COL_WILDCARD,
    "mrd": COL_MRD,
    "nvos_gnmi": COL_GNMI,
    "nmx_t": COL_NMXT,
    "nvos_cli_2503": COL_CLI_2503,
    "nvos_cli_2502": COL_CLI_2502,
    "onboard_dbus": COL_ONBOARD,
    "otlp": COL_OTLP,
}

NA_VALUES = {"", "NA", "N/A", "#N/A", "NONE", "TBD", "N.A."}
GENERIC_INFRA_FAMILIES = {
    "Redfish TelemetryService",
    "Redfish Fabric/Switch/Port",
    "NVOS gNMI",
    "NMX-T",
}


def clean(value: str | None) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def has_value(value: str | None) -> bool:
    c = clean(value)
    return bool(c) and c.upper() not in NA_VALUES


def yes(value: str | None) -> bool:
    return clean(value).lower() == "yes"


def snake(metric: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", metric.lower()).strip("_")


def load_coverage(coverage_json: Path) -> dict[int, dict[str, str]]:
    if not coverage_json.exists():
        return {}
    data = json.loads(coverage_json.read_text())
    out: dict[int, dict[str, str]] = {}
    for section in ("covered", "partial", "gaps"):
        for item in data.get(section, []):
            out[int(item["row"])] = item
    return out


def extract_sources(row: dict[str, str]) -> dict[str, str]:
    sources = {}
    for name, col in SOURCE_COLUMNS.items():
        val = row.get(col, "")
        if has_value(val):
            sources[name] = clean(val)
    return sources


def source_family(source_name: str, value: str) -> str:
    text = f"{source_name} {value}".lower()
    if "telemetryservice" in text or "metricreport" in text or source_name == "mrd":
        return "Redfish TelemetryService"
    if source_name.startswith("redfish"):
        return "Redfish Fabric/Switch/Port"
    if source_name == "nvos_gnmi":
        return "NVOS gNMI"
    if source_name == "nmx_t":
        return "NMX-T"
    if source_name.startswith("nvos_cli"):
        return "NVOS CLI"
    if source_name == "onboard_dbus":
        return "Onboard DBus"
    if source_name == "otlp":
        return "OTLP"
    return source_name


def choose_sources(row: dict[str, str], sources: dict[str, str], metric: str = "") -> tuple[str, str, str, str]:
    existing_primary = {
        "PORT-RCV-ERRORS": "nvos_gnmi",
        "PORT-XMIT-CONSTRAINTS-ERRORS": "nvos_gnmi",
        "EFFECTIVE-BER": "nvos_gnmi",
        "SYMBOL-BER": "nvos_gnmi",
        "PHY-SYMBOL-ERRORS": "nmx_t",
    }
    if not sources:
        return (
            "SOURCE UNLISTED live source resolution",
            "",
            "No catalog source listed for GB200 row; resolve during live validation",
            "source-resolution required before live signoff",
        )

    availability = clean(row.get(COL_AVAIL, "")).upper()
    tray = yes(row.get("Applicable for\nGB200 NVL NvswitchTray"))
    hmc_or_bmc = yes(row.get("Applicable for \nGB200 NVL HMC")) or yes(row.get("Applicable for \nGB200 NVL BMC"))
    tray_only = tray and not hmc_or_bmc

    ordered_names = []
    if any(k in sources for k in ("mrd",)):
        ordered_names.append("mrd")
    if any(k in sources for k in ("redfish_gb", "redfish_wildcard", "redfish_dgx_or_c2")) and not tray_only:
        ordered_names.extend(["redfish_wildcard", "redfish_gb", "redfish_dgx_or_c2"])
    if "nvos_gnmi" in sources:
        if "IB" in availability or tray_only:
            ordered_names.insert(0, "nvos_gnmi")
        else:
            ordered_names.append("nvos_gnmi")
    if "nmx_t" in sources:
        ordered_names.append("nmx_t")
    if "nvos_cli_2503" in sources:
        ordered_names.append("nvos_cli_2503")
    if "nvos_cli_2502" in sources:
        ordered_names.append("nvos_cli_2502")
    if "onboard_dbus" in sources:
        ordered_names.append("onboard_dbus")
    if "otlp" in sources:
        ordered_names.append("otlp")

    seen = set()
    available_ordered = []
    for name in ordered_names:
        if name in sources and name not in seen:
            seen.add(name)
            available_ordered.append(name)
    for name in sources:
        if name not in seen:
            available_ordered.append(name)

    if metric in existing_primary and existing_primary[metric] in available_ordered:
        available_ordered.remove(existing_primary[metric])
        available_ordered.insert(0, existing_primary[metric])

    primary_name = available_ordered[0]
    fallback_name = available_ordered[1] if len(available_ordered) > 1 else ""
    primary = source_family(primary_name, sources[primary_name])
    fallback = source_family(fallback_name, sources[fallback_name]) if fallback_name else ""
    precedence_parts = []
    for name in available_ordered:
        family = source_family(name, sources[name])
        if family not in precedence_parts:
            precedence_parts.append(family)
    precedence = " then ".join(precedence_parts)
    return primary, fallback, precedence, "one canonical series unless source-qualified duplicate is justified"


def is_redfish_sensor_range(redfish_path: str) -> bool:
    return "/Sensors/" in redfish_path and (
        "ReadingRangeMax" in redfish_path or "ReadingRangeMin" in redfish_path
    )


def sensor_range_surface(redfish_path: str) -> str:
    if "ReadingRangeMax" in redfish_path:
        return "hw_sensor {reading_type}_range_max MetricSample with sensor_range=reading_range_max"
    if "ReadingRangeMin" in redfish_path:
        return "hw_sensor {reading_type}_range_min MetricSample with sensor_range=reading_range_min"
    return "hw_sensor range MetricSample"


def target_collector(primary: str, sources: dict[str, str], redfish_path: str) -> str:
    if is_redfish_sensor_range(redfish_path):
        return "existing SensorsCollector range emission when include_sensor_thresholds=true"
    if primary.startswith("SOURCE UNLISTED"):
        return "live source resolution required; generic Redfish/NMX-T/gNMI collectors will expose the row if emitted"
    if primary == "Redfish TelemetryService":
        return "new NvSwitchTelemetryServiceCollector behind collectors.telemetry_service"
    if primary == "Redfish Fabric/Switch/Port":
        return "new NvSwitchRedfishCollector for switch BMC endpoints"
    if primary == "NVOS gNMI":
        return "extend NvueGnmiCollector sample paths/processors"
    if primary == "NMX-T":
        return "extend NmxtCollector mapping"
    if primary == "NVOS CLI":
        if "nvos_gnmi" in sources:
            return "prefer NVOS gNMI equivalent; live source-equivalence required if no streamed equivalent exists"
        return "live source-equivalence required; prefer Redfish TelemetryService, NVOS gNMI, or NMX-T before adding CLI collector"
    if primary == "Onboard DBus":
        return "live source-equivalence required; prefer Redfish exposure before adding DBus collector"
    if primary == "OTLP":
        return "live source-equivalence required; upstream OTLP source contract needed if not exposed elsewhere"
    return "TBD collector"


def has_generic_infra_source(sources: dict[str, str]) -> bool:
    return any(
        source_family(source_name, source_value) in GENERIC_INFRA_FAMILIES
        for source_name, source_value in sources.items()
    )


def branch_coverage(
    primary: str,
    sources: dict[str, str],
    cov_status: str,
    cov_reason: str,
) -> tuple[str, str, str]:
    if cov_status.startswith("covered"):
        return cov_status, "already-covered-regression-required", cov_reason

    if primary.startswith("SOURCE UNLISTED") or not sources:
        return (
            "source_resolution_required",
            "requires-live-source-resolution",
            "Catalog row has no source path/name; live validation must identify a Redfish, NMX-T, or gNMI source if the device emits it.",
        )

    if has_generic_infra_source(sources):
        return (
            "covered_generic_infra_unvalidated",
            "covered-by-generic-infra-requires-live-validation",
            "GB200 branch generic Redfish MetricReport, NMX-T, and NVUE gNMI preservation can emit this row; live hardware validation must confirm the concrete device path/name.",
        )

    return (
        "source_equivalent_required",
        "requires-live-source-equivalent",
        "Catalog lists only source families that are not collected directly; live validation must find an equivalent Redfish, NMX-T, or gNMI exposure before signoff.",
    )


def emitted_surface(metric: str, data_type: str, coverage: str, redfish_path: str) -> str:
    if is_redfish_sensor_range(redfish_path):
        return sensor_range_surface(redfish_path)
    existing = {
        "PORT-RCV-ERRORS": "existing interface_in_errors MetricSample",
        "PORT-XMIT-CONSTRAINTS-ERRORS": "existing interface_out_errors MetricSample",
        "EFFECTIVE-BER": "existing interface_effective_ber MetricSample",
        "SYMBOL-BER": "existing interface_symbol_ber MetricSample",
        "PHY-SYMBOL-ERRORS": "existing switch_nmxt symbol_errors MetricSample",
    }
    if metric in existing and coverage.startswith("covered"):
        return existing[metric]
    dtype = clean(data_type).lower()
    base = f"nvswitch_{snake(metric)}"
    if "text" in dtype or "string" in dtype:
        return f"{base} as inventory/info event or state metric with bounded labels"
    if "bool" in dtype or "enum" in dtype or "status" in dtype:
        return f"{base} as numeric state MetricSample"
    return f"{base} MetricSample"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rows-csv",
        required=True,
        type=Path,
        help="Sanitized NVSWITCH rows extracted from the telemetry catalog workbook.",
    )
    parser.add_argument(
        "--coverage-json",
        required=True,
        type=Path,
        help="Coverage heuristic JSON for the sanitized NVSWITCH rows.",
    )
    parser.add_argument(
        "--out-csv",
        default=DEFAULT_OUT_CSV,
        type=Path,
        help="Output CSV path.",
    )
    parser.add_argument(
        "--out-md",
        default=DEFAULT_OUT_MD,
        type=Path,
        help="Output Markdown summary path.",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main() -> None:
    args = parse_args()
    rows_csv = args.rows_csv.resolve()
    coverage_json = args.coverage_json.resolve()
    out_csv = args.out_csv.resolve()
    out_md = args.out_md.resolve()
    out_dir = out_csv.parent

    coverage = load_coverage(coverage_json)
    out_dir.mkdir(parents=True, exist_ok=True)
    with rows_csv.open(newline="") as f:
        rows = list(csv.DictReader(f))

    out_rows = []
    for row in rows:
        if "nvswitch" not in clean(row.get(COL_DEVICE, "")).lower():
            continue
        applicable_cols = [col for col in GB200_COLUMNS if yes(row.get(col))]
        if not applicable_cols:
            continue
        row_no = int(row["__ods_row_number"])
        metric = clean(row.get(COL_METRIC, ""))
        sources = extract_sources(row)
        primary, fallback, precedence, duplicate_policy = choose_sources(row, sources, metric)
        cov = coverage.get(row_no, {})
        cov_status = clean(cov.get("coverage", "gap")) or "gap"
        cov_reason = clean(cov.get("coverage_reason", ""))
        redfish_path = clean(row.get(COL_URI_DOMAIN)) or clean(row.get(COL_WILDCARD)) or clean(row.get(COL_REDFISH_GB)) or clean(row.get(COL_MRD))
        branch_cov_status, implementation_status, branch_cov_reason = branch_coverage(
            primary,
            sources,
            cov_status,
            cov_reason,
        )

        out_rows.append({
            "catalog_row": row_no,
            "guid": clean(row.get(COL_GUID, "")),
            "metric_param_name": metric,
            "description": clean(row.get(COL_DESC, "")),
            "category": clean(row.get(COL_CATEGORY, "")),
            "data_type": clean(row.get(COL_DATA_TYPE, "")),
            "gb200_applicability": "; ".join(col.replace("Applicable for", "").replace("\n", " ").strip() for col in applicable_cols),
            "availability": clean(row.get(COL_AVAIL, "")),
            "source_families": "; ".join(dict.fromkeys(source_family(k, v) for k, v in sources.items())),
            "primary_source": primary,
            "fallback_source": fallback,
            "source_precedence": precedence,
            "duplicate_alias_policy": duplicate_policy,
            "target_collector": target_collector(primary, sources, redfish_path),
            "target_emitted_surface": emitted_surface(metric, row.get(COL_DATA_TYPE, ""), cov_status, redfish_path),
            "current_coverage": branch_cov_status,
            "implementation_status": implementation_status,
            "coverage_reason": branch_cov_reason,
            "redfish_or_mrd_path": redfish_path,
            "nvos_gnmi_path": clean(row.get(COL_GNMI, "")),
            "nmx_t_field": clean(row.get(COL_NMXT, "")),
            "nvos_cli_reference": clean(row.get(COL_CLI_2503, "")) or clean(row.get(COL_CLI_2502, "")),
            "onboard_dbus_reference": clean(row.get(COL_ONBOARD, "")),
            "test_fixture_plan": "required before review: parser/unit fixture plus metric emission assertion; live GB evidence during post-review validation",
            "live_validation_plan": "validate on GB200 NVLink Switch BMC/HOST after branch build-test-lint review",
        })

    fieldnames = list(out_rows[0].keys()) if out_rows else []
    out_dir.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(out_rows)

    counts = Counter(r["implementation_status"] for r in out_rows)
    primary_counts = Counter(r["primary_source"] for r in out_rows)
    coverage_counts = Counter(r["current_coverage"] for r in out_rows)
    md = [
        "# NVSWITCH telemetry GB200 source matrix",
        "",
        "Generated from sanitized Telemetry Catalog extraction artifacts for rows where `Device (CompClass)` is NVSWITCH and one of the GB200 columns is `Yes`:",
        "",
        "- `Applicable for GB200 NVL HMC`",
        "- `Applicable for GB200 NVL BMC`",
        "- `Applicable for GB200 NVL NvswitchTray`",
        "",
        f"CSV matrix: `{display_path(out_csv)}`",
        "",
        "## Counts",
        "",
        f"- Total GB200-applicable NVSWITCH rows: {len(out_rows)}",
        "",
        "### Implementation status",
        "",
    ]
    for key, value in sorted(counts.items()):
        md.append(f"- {key}: {value}")
    md.extend(["", "### Branch coverage status", ""])
    for key, value in sorted(coverage_counts.items()):
        md.append(f"- {key}: {value}")
    md.extend(["", "### Primary source", ""])
    for key, value in sorted(primary_counts.items()):
        md.append(f"- {key}: {value}")
    md.extend([
        "",
        "## GB200 branch implementation coverage",
        "",
        "The `nvswitch_telemetry_gaps` branch implements common GB+VR-friendly collector infrastructure for the GB200 phase:",
        "",
        "- Redfish BMC: enabled `nv-redfish` `telemetry-service`, added a switch-BMC-only TelemetryService collector, and emits every numeric/boolean/string `MetricReport` value as `redfish_telemetry_service` samples with report and source-property labels.",
        "- BMC proxy: widened TelemetryService ACLs to `MetricReportDefinitions/*` and `MetricReports/*` so live GB200 validation is not limited to `NvidiaNMMetrics_0`.",
        "- NMX-T HOST: preserves all numeric Prometheus samples instead of dropping unknown metric names; legacy `Effective_BER`, `Symbol_Errors`, and `Link_Down` metric names remain canonical.",
        "- NVUE gNMI HOST: subscribes to `components`, `interfaces`, and `platform-general`; known current metrics keep their existing names, and previously unmapped leaves are emitted as source-qualified `nvswitch_*` samples.",
        "- Config: `collectors.telemetry_service` is disabled by default, and `collectors.nvue.gnmi.paths.platform_general_enabled` is an explicit opt-in path gate; the example and live-validation configs enable the full GB200 switch collector set.",
        "",
        "The generic-preservation surfaces are behavior-locked by unit tests before live hardware validation:",
        "",
        "- Redfish TelemetryService: `metric_report_values_emit_numeric_and_info_samples` covers numeric, string/info, and boolean/state MetricReport values.",
        "- NMX-T: `generic_metric_key_includes_sorted_extra_label_identity` and `generic_metric_key_distinguishes_same_port_samples_by_extra_labels` cover stable key identity for unknown Prometheus samples with extra labels.",
        "- NVUE gNMI: `unmapped_interface_leaf_emits_catalog_metric_sample` and `platform_general_string_leaf_emits_info_metric` cover previously unmapped interface leaves and platform-general string leaves.",
        "",
        "Rows that still have no catalog-listed source remain in scope: `CABLE-SNR-MEDIA-LANE-N` and `CABLE-SNR-HOST-LANE-N` are marked `requires-live-source-resolution` and must be checked during live validation. The generic Redfish MetricReport, NMX-T, and gNMI preservation paths will expose them if the device emits them; if not, open a source-owner follow-up immediately.",
        "",
        "## Execution rules",
        "",
        "- Every row must keep `primary_source`, `fallback_source`, `source_precedence`, and `duplicate_alias_policy` populated before implementation is marked complete.",
        "- Default duplicate policy is one canonical series per catalog row; source-qualified duplicates require source-path proof and consumer-safety rationale.",
        "- Generic-preserved metrics must keep bounded identity labels: report id/URI/definition and metric id/property/identity for Redfish MetricReports, raw source metric plus sorted source-label identity for NMX-T, and full gNMI path plus endpoint/entity labels for gNMI. Redfish internal keys must use escaped raw MetricId/MetricProperty identity, and NMX-T generic keys must escape raw port/source/node/label identity, to avoid aliasing. Raw string metric values must not be emitted as labels.",
        "- Rows marked `requires-live-source-resolution` or `requires-live-source-equivalent` remain in scope; they require live source proof or immediate escalation before GB200 signoff.",
        "- Live GB200 validation happens after the branch is built, tested, linted, pushed, and reviewed.",
        "",
    ])
    out_md.write_text("\n".join(md) + "\n")
    print(f"wrote {out_csv}")
    print(f"wrote {out_md}")
    print(f"rows {len(out_rows)}")


if __name__ == "__main__":
    main()
