import json
import os
from typing import Dict, Tuple

import pandas as pd

from app.ingestion.common import best_confidence, safe_number, unique_list
from app.ingestion.nist_parser import parse_nist_oscal
from app.ingestion.remediation_matcher import match_remediation_hint
from app.ingestion.threat_report import extract_threat_report_terms


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
            safe_number(frame, column)

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
            campaign_names=("campaign_name", unique_list),
            threat_actors=("threat_actor", unique_list),
            threat_summaries=("summary", unique_list),
            exploit_maturity=("exploit_maturity", unique_list),
            target_regions=("target_region", unique_list),
            target_sectors=("target_sector", unique_list),
            ransomware_associations=("ransomware_association", unique_list),
            intel_confidence=("confidence", best_confidence),
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

    hint_matches = df.apply(lambda row: match_remediation_hint(row, remediation_hints), axis=1)
    df["hint_finding_type"] = hint_matches.apply(lambda item: item[0])
    df["remediation_hint"] = hint_matches.apply(lambda item: item[1])
    df["hint_priority"] = hint_matches.apply(lambda item: item[2])
    df["hint_validation_evidence"] = hint_matches.apply(lambda item: item[3])

    report_matches = df.apply(lambda row: extract_threat_report_terms(threat_report_text, row), axis=1)
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
