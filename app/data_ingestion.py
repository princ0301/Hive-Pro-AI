import json
import os
import re
from typing import Dict, Iterable, List, Tuple

import pandas as pd


def _iter_controls(controls: Iterable[dict]) -> Iterable[dict]:
    for control in controls or []:
        yield control
        nested_controls = control.get("controls", [])
        if nested_controls:
            yield from _iter_controls(nested_controls)


def _collect_prose(parts: Iterable[dict]) -> List[str]:
    prose_segments: List[str] = []
    for part in parts or []:
        prose = (part.get("prose") or "").strip()
        if prose:
            prose_segments.append(prose)
        nested = part.get("parts", [])
        if nested:
            prose_segments.extend(_collect_prose(nested))
    return prose_segments


def parse_nist_oscal(file_path: str) -> pd.DataFrame:
    nist_controls = []
    with open(file_path, "r", encoding="utf-8") as handle:
        nist_data = json.load(handle)

    for group in nist_data.get("catalog", {}).get("groups", []):
        group_id = (group.get("id") or "").upper()
        group_title = group.get("title", "")
        for control in _iter_controls(group.get("controls", [])):
            control_id = (control.get("id") or "").upper()
            title = control.get("title", "")
            prose_segments = _collect_prose(control.get("parts", []))
            description = " ".join(segment for segment in prose_segments if segment).strip() or title
            family = control_id.split("-")[0] if "-" in control_id else group_id

            nist_controls.append(
                {
                    "id": control_id,
                    "title": title,
                    "family": family,
                    "group_id": group_id,
                    "group_title": group_title,
                    "description": description,
                }
            )

    nist_df = pd.DataFrame(nist_controls).drop_duplicates(subset=["id"])
    return nist_df


def _safe_number(frame: pd.DataFrame, column: str) -> None:
    if column in frame.columns:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")


def _normalize_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "yes", "1", "y"}


def _unique_list(values: Iterable[object]) -> List[str]:
    cleaned = []
    for value in values:
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def _best_confidence(values: Iterable[object]) -> str:
    ranking = {"low": 1, "medium": 2, "high": 3}
    best = "Unknown"
    best_score = 0
    for value in values:
        score = ranking.get(str(value).strip().lower(), 0)
        if score > best_score:
            best_score = score
            best = str(value).strip().title()
    return best


def _tokenize(text: str) -> set:
    stop_words = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "into",
        "via",
        "server",
        "application",
        "prod",
        "production",
        "older",
        "version",
        "missing",
        "outdated",
        "remote",
        "code",
        "execution",
        "exposed",
    }
    tokens = set(re.findall(r"[a-z0-9]{3,}", text.lower()))
    return {token for token in tokens if token not in stop_words}


def _match_remediation_hint(row: pd.Series, hints_df: pd.DataFrame) -> Tuple[str, str, str, str]:
    context = " ".join(
        [
            str(row.get("vulnerability_name", "")),
            str(row.get("affected_component", "")),
            str(row.get("asset_type", "")),
            str(row.get("vendor_product", "")),
            str(row.get("cve", "")),
        ]
    )
    context_tokens = _tokenize(context)

    best_score = 0
    best_match = None
    for _, hint_row in hints_df.iterrows():
        hint_tokens = _tokenize(str(hint_row.get("finding_type", "")))
        overlap = len(context_tokens & hint_tokens)
        if overlap > best_score:
            best_score = overlap
            best_match = hint_row

    if best_match is None or best_score == 0:
        return "", "", "", ""

    return (
        str(best_match.get("finding_type", "")),
        str(best_match.get("recommended_action", "")),
        str(best_match.get("priority_hint", "")),
        str(best_match.get("validation_evidence", "")),
    )


def _extract_threat_report_terms(report_text: str, row: pd.Series) -> List[str]:
    matches = []
    search_terms = _unique_list(
        [row.get("cve")] + row.get("campaign_names", []) + row.get("threat_actors", [])
    )
    report_lower = report_text.lower()
    for term in search_terms:
        if term and str(term).lower() in report_lower:
            matches.append(str(term))
    return matches


def load_all_data(data_dir: str = "data") -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, object]]:
    assets = pd.read_csv(os.path.join(data_dir, "assets.csv"))
    vulns = pd.read_csv(os.path.join(data_dir, "vulnerabilities.csv"))
    threat_intel = pd.read_csv(os.path.join(data_dir, "threat_intelligence.csv"))
    services = pd.read_csv(os.path.join(data_dir, "business_services.csv"))
    remediation_hints = pd.read_csv(os.path.join(data_dir, "remediation_guidance.csv"))

    for frame, numeric_columns in [
        (assets, ["last_seen_days"]),
        (vulns, ["cvss", "days_open"]),
        (services, ["rto_hours"]),
    ]:
        for column in numeric_columns:
            _safe_number(frame, column)

    with open(os.path.join(data_dir, "kev.json"), "r", encoding="utf-8") as handle:
        kev_data = json.load(handle)
    kev_df = pd.DataFrame(kev_data["vulnerabilities"])[
        ["cveID", "dateAdded", "requiredAction", "knownRansomwareCampaignUse"]
    ].rename(
        columns={
            "cveID": "cve",
            "dateAdded": "kev_date_added",
            "requiredAction": "kev_required_action",
            "knownRansomwareCampaignUse": "kev_ransomware_use",
        }
    )

    nist_df = parse_nist_oscal(os.path.join(data_dir, "nist_800_53.json"))

    with open(os.path.join(data_dir, "synthetic_threat_report.md"), "r", encoding="utf-8") as handle:
        threat_report_text = handle.read()

    df = pd.merge(vulns, assets, on="asset_id", how="left")
    df = pd.merge(df, services, on="business_service", how="left")
    df = pd.merge(df, kev_df, on="cve", how="left")
    df["in_kev"] = df["kev_date_added"].notna()

    intel_summary = (
        threat_intel.groupby("matched_cve_or_control")
        .agg(
            campaign_names=("campaign_name", _unique_list),
            threat_actors=("threat_actor", _unique_list),
            threat_summaries=("summary", _unique_list),
            exploit_maturity=("exploit_maturity", _unique_list),
            target_regions=("target_region", _unique_list),
            target_sectors=("target_sector", _unique_list),
            ransomware_associations=("ransomware_association", _unique_list),
            intel_confidence=("confidence", _best_confidence),
            active_last_seen=("active_last_seen", "max"),
        )
        .reset_index()
    )
    df = pd.merge(
        df,
        intel_summary,
        left_on="cve",
        right_on="matched_cve_or_control",
        how="left",
    )

    list_columns = [
        "campaign_names",
        "threat_actors",
        "threat_summaries",
        "exploit_maturity",
        "target_regions",
        "target_sectors",
        "ransomware_associations",
    ]
    for column in list_columns:
        df[column] = df[column].apply(lambda value: value if isinstance(value, list) else [])

    df["has_active_threat_match"] = df["campaign_names"].apply(bool)
    df["has_ransomware_threat"] = df["ransomware_associations"].apply(
        lambda values: any(str(value).strip().lower() == "yes" for value in values)
    )
    df["in_threat_report"] = False
    df["threat_report_matches"] = [[] for _ in range(len(df))]

    hint_matches = df.apply(lambda row: _match_remediation_hint(row, remediation_hints), axis=1)
    df["hint_finding_type"] = hint_matches.apply(lambda item: item[0])
    df["remediation_hint"] = hint_matches.apply(lambda item: item[1])
    df["hint_priority"] = hint_matches.apply(lambda item: item[2])
    df["hint_validation_evidence"] = hint_matches.apply(lambda item: item[3])

    report_matches = df.apply(lambda row: _extract_threat_report_terms(threat_report_text, row), axis=1)
    df["threat_report_matches"] = report_matches
    df["in_threat_report"] = df["threat_report_matches"].apply(bool)

    metadata = {
        "assets_count": int(len(assets)),
        "vulnerabilities_count": int(len(vulns)),
        "threat_records_count": int(len(threat_intel)),
        "services_count": int(len(services)),
        "threat_report_excerpt": threat_report_text[:1200],
    }
    return df, nist_df, metadata
