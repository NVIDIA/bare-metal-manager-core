#!/usr/bin/env python3
"""Generate the GB200 NVSWITCH telemetry source matrix from OMX catalog artifacts.

Input artifacts are intentionally under .omx because the source workbook is not tracked.
The generated CSV and Markdown summary are tracked under docs for MR review.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROWS_CSV = ROOT / ".omx/artifacts/nvswitch_rows.csv"
COVERAGE_JSON = ROOT / ".omx/artifacts/nvswitch_catalog_coverage_heuristic.json"
OUT_DIR = ROOT / "docs/architecture/health"
OUT_CSV = OUT_DIR / "nvswitch_telemetry_gb200_matrix.csv"
OUT_MD = OUT_DIR / "nvswitch_telemetry_gb200_matrix.md"

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


def load_coverage() -> dict[int, dict[str, str]]:
    if not COVERAGE_JSON.exists():
        return {}
    data = json.loads(COVERAGE_JSON.read_text())
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
        return "BLOCKER source resolution", "", "No catalog source listed for GB200 row", "source-resolution blocker"

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


def target_collector(primary: str, sources: dict[str, str]) -> str:
    if primary == "BLOCKER source resolution":
        return "BLOCKER: source resolution required"
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
            return "prefer NVOS gNMI equivalent; CLI-only path is blocker if no streamed equivalent exists"
        return "BLOCKER: no current NVOS CLI collector; source equivalent required"
    if primary == "Onboard DBus":
        return "prefer Redfish exposure; otherwise BLOCKER: no current DBus collector"
    if primary == "OTLP":
        return "BLOCKER: upstream OTLP source contract required"
    return "TBD collector"


def emitted_surface(metric: str, data_type: str, coverage: str) -> str:
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


def main() -> None:
    coverage = load_coverage()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with ROWS_CSV.open(newline="") as f:
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
        if primary.startswith("BLOCKER"):
            implementation_status = "blocker-source-resolution"
        elif cov_status.startswith("covered"):
            implementation_status = "already-covered-regression-required"
        elif cov_status.startswith("partial"):
            implementation_status = "partial-needs-implementation"
        else:
            implementation_status = "gap-needs-implementation"

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
            "target_collector": target_collector(primary, sources),
            "target_emitted_surface": emitted_surface(metric, row.get(COL_DATA_TYPE, ""), cov_status),
            "current_coverage": cov_status,
            "implementation_status": implementation_status,
            "coverage_reason": cov_reason,
            "redfish_or_mrd_path": clean(row.get(COL_URI_DOMAIN)) or clean(row.get(COL_WILDCARD)) or clean(row.get(COL_REDFISH_GB)) or clean(row.get(COL_MRD)),
            "nvos_gnmi_path": clean(row.get(COL_GNMI, "")),
            "nmx_t_field": clean(row.get(COL_NMXT, "")),
            "nvos_cli_reference": clean(row.get(COL_CLI_2503, "")) or clean(row.get(COL_CLI_2502, "")),
            "onboard_dbus_reference": clean(row.get(COL_ONBOARD, "")),
            "test_fixture_plan": "required: parser fixture plus metric emission assertion; live GB evidence before review pause",
            "live_validation_plan": "validate on GB200 NVLink Switch BMC/HOST after branch build-test-lint review",
        })

    fieldnames = list(out_rows[0].keys()) if out_rows else []
    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    counts = Counter(r["implementation_status"] for r in out_rows)
    primary_counts = Counter(r["primary_source"] for r in out_rows)
    coverage_counts = Counter(r["current_coverage"] for r in out_rows)
    md = [
        "# NVSWITCH telemetry GB200 source matrix",
        "",
        "Generated from `.omx/artifacts/nvswitch_rows.csv` for rows where `Device (CompClass)` is NVSWITCH and one of the GB200 columns is `Yes`:",
        "",
        "- `Applicable for GB200 NVL HMC`",
        "- `Applicable for GB200 NVL BMC`",
        "- `Applicable for GB200 NVL NvswitchTray`",
        "",
        f"CSV matrix: `{OUT_CSV.relative_to(ROOT)}`",
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
    md.extend(["", "### Current coverage", ""])
    for key, value in sorted(coverage_counts.items()):
        md.append(f"- {key}: {value}")
    md.extend(["", "### Primary source", ""])
    for key, value in sorted(primary_counts.items()):
        md.append(f"- {key}: {value}")
    md.extend([
        "",
        "## Execution rules",
        "",
        "- Every row must keep `primary_source`, `fallback_source`, `source_precedence`, and `duplicate_alias_policy` populated before implementation is marked complete.",
        "- Default duplicate policy is one canonical series per catalog row; source-qualified duplicates require source-path proof and consumer-safety rationale.",
        "- Rows marked `blocker-source-resolution` are not deferred; they require immediate source-resolution or escalation.",
        "- Live GB200 validation happens after the branch is built, tested, linted, pushed, and reviewed.",
        "",
    ])
    OUT_MD.write_text("\n".join(md))
    print(f"wrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")
    print(f"rows {len(out_rows)}")


if __name__ == "__main__":
    main()
