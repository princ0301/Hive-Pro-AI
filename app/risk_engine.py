from typing import Dict, List

import pandas as pd


def _add_component(components: List[Dict[str, object]], label: str, points: float, detail: str) -> None:
    if points <= 0:
        return
    components.append({"label": label, "points": round(points, 1), "detail": detail})


def _criticality_points(value: object) -> float:
    mapping = {"critical": 18, "high": 12, "medium": 6, "low": 2}
    return mapping.get(str(value).strip().lower(), 0)


def _revenue_points(value: object) -> float:
    mapping = {"critical": 16, "high": 10, "medium": 5, "low": 1}
    return mapping.get(str(value).strip().lower(), 0)


def _environment_points(value: object) -> float:
    mapping = {"production": 12, "staging": 4, "development": 1}
    return mapping.get(str(value).strip().lower(), 0)


def _compliance_points(value: object) -> float:
    scope = str(value).strip().lower()
    points = 0
    if "pci dss" in scope:
        points += 6
    if "gdpr" in scope or "pdpl" in scope:
        points += 5
    if "soc 2" in scope:
        points += 3
    if "iso 27001" in scope:
        points += 2
    return min(points, 10)


def _days_open_points(days_open: object, patch_available: object) -> float:
    days = pd.to_numeric(days_open, errors="coerce")
    if pd.isna(days):
        return 0
    if days >= 180:
        points = 10
    elif days >= 90:
        points = 8
    elif days >= 30:
        points = 5
    else:
        points = 2

    if str(patch_available).strip().lower() == "yes":
        points += 2
    return points


def calculate_risk_components(row: pd.Series) -> Dict[str, object]:
    components: List[Dict[str, object]] = []

    cvss = float(pd.to_numeric(row.get("cvss"), errors="coerce") or 0)
    _add_component(components, "CVSS severity", min(cvss * 5, 50), f"CVSS {cvss:.1f} indicates high technical severity.")

    if str(row.get("internet_exposed", "")).strip().lower() == "yes":
        _add_component(
            components,
            "Internet exposure",
            18,
            "The affected asset is internet-facing, making it directly reachable for first-stage attacks.",
        )

    if str(row.get("asset_exposure", "")).strip().lower() == "internet":
        _add_component(
            components,
            "Internet-facing vulnerability path",
            7,
            "The vulnerability record itself is marked as exposed to the internet.",
        )

    if str(row.get("exploit_available", "")).strip().lower() == "yes":
        _add_component(
            components,
            "Exploit availability",
            12,
            "Exploit code or active exploitation material is already available to attackers.",
        )

    if str(row.get("auth_required", "")).strip().lower() == "no":
        _add_component(
            components,
            "No authentication required",
            8,
            "Attackers do not need valid credentials to attempt exploitation.",
        )

    if bool(row.get("in_kev")):
        _add_component(
            components,
            "CISA KEV match",
            22,
            "This CVE appears in the CISA Known Exploited Vulnerabilities catalog.",
        )

    if str(row.get("kev_ransomware_use", "")).strip().lower() == "known":
        _add_component(
            components,
            "Known ransomware use",
            16,
            "CISA KEV flags this vulnerability as being used in ransomware campaigns.",
        )

    if bool(row.get("has_active_threat_match")):
        campaign_count = len(row.get("campaign_names", []))
        _add_component(
            components,
            "Matched threat campaign",
            18 + min(campaign_count, 3) * 2,
            f"Active threat intelligence directly references this CVE across {campaign_count} matching campaign record(s).",
        )

    if bool(row.get("has_ransomware_threat")):
        _add_component(
            components,
            "Ransomware association",
            14,
            "The matched threat campaign includes ransomware or double-extortion behavior.",
        )

    if bool(row.get("in_threat_report")):
        _add_component(
            components,
            "Regional advisory match",
            8,
            "The same CVE, actor, or campaign is called out in this week's MDR advisory for the region.",
        )

    env_points = _environment_points(row.get("environment"))
    _add_component(
        components,
        "Environment criticality",
        env_points,
        f"The vulnerable asset sits in the {row.get('environment', 'unknown')} environment.",
    )

    asset_crit_points = _criticality_points(row.get("criticality"))
    _add_component(
        components,
        "Asset criticality",
        asset_crit_points,
        f"The asset is marked as {row.get('criticality', 'unknown')} criticality in inventory.",
    )

    revenue_points = _revenue_points(row.get("revenue_impact"))
    _add_component(
        components,
        "Business impact",
        revenue_points,
        f"The affected business service has {row.get('revenue_impact', 'unknown')} revenue impact.",
    )

    if str(row.get("customer_facing", "")).strip().lower() == "yes":
        _add_component(
            components,
            "Customer-facing service",
            10,
            "The impacted business service is customer-facing and disruption would be externally visible.",
        )

    compliance_points = _compliance_points(row.get("compliance_scope"))
    _add_component(
        components,
        "Compliance scope",
        compliance_points,
        f"The service sits in {row.get('compliance_scope', 'limited')} compliance scope.",
    )

    if str(row.get("edr_installed", "")).strip().lower() == "no":
        _add_component(
            components,
            "Missing compensating control",
            12,
            "EDR is not installed on the affected asset, reducing detection and containment capability.",
        )

    aging_points = _days_open_points(row.get("days_open"), row.get("patch_available"))
    _add_component(
        components,
        "Remediation delay",
        aging_points,
        f"The vulnerability has been open for {int(pd.to_numeric(row.get('days_open'), errors='coerce') or 0)} days"
        f"{' and a patch is available' if str(row.get('patch_available', '')).strip().lower() == 'yes' else ''}.",
    )

    total_score = round(sum(component["points"] for component in components), 1)
    top_factors = sorted(components, key=lambda item: item["points"], reverse=True)[:5]

    return {
        "risk_score": total_score,
        "risk_components": components,
        "top_factors": top_factors,
    }


def _build_plain_english_reason(row: pd.Series) -> str:
    factor_text = [factor["detail"] for factor in row["top_factors"][:3]]
    if not factor_text:
        return "This item ranks highly due to a combination of technical severity and business exposure."
    return " ".join(factor_text)


def get_top_risks(df: pd.DataFrame, top_n: int = 5) -> List[Dict[str, object]]:
    scored = df.copy()
    component_data = scored.apply(calculate_risk_components, axis=1)
    scored["risk_score"] = component_data.apply(lambda item: item["risk_score"])
    scored["risk_components"] = component_data.apply(lambda item: item["risk_components"])
    scored["top_factors"] = component_data.apply(lambda item: item["top_factors"])
    scored["plain_english_reason"] = scored.apply(_build_plain_english_reason, axis=1)

    scored = scored.sort_values(by=["risk_score", "cvss", "days_open"], ascending=[False, False, False])
    selected_records: List[Dict[str, object]] = []
    seen_exposures = set()

    for record in scored.to_dict(orient="records"):
        exposure_key = (record.get("business_service"), record.get("cve"))
        if exposure_key in seen_exposures:
            continue
        seen_exposures.add(exposure_key)
        selected_records.append(record)
        if len(selected_records) >= top_n:
            break

    return selected_records
