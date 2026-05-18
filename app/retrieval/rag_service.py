from typing import Dict

from app.retrieval.nist_retriever import NISTRetriever


class RAGService:
    def __init__(self, nist_df):
        self.retriever = NISTRetriever(nist_df)

    def get_remediation_guidance(self, risk_record: Dict[str, object]) -> Dict[str, str]:
        return self.retriever.get_remediation_guidance(risk_record)

    def _remediation_summary(self, control: Dict[str, str], risk_record: Dict[str, object]) -> str:
        hint = str(risk_record.get("remediation_hint", "")).strip()
        if hint:
            return (
                f"NIST control {control['id']} ({control['title']}) is the closest match here. "
                f"It recommends {control['recommendation'].rstrip('.').lower()}. "
                f"As an immediate operational step, {hint.rstrip('.').lower()}."
            )
        return (
            f"NIST control {control['id']} ({control['title']}) is the closest match here. "
            f"It recommends {control['recommendation'].rstrip('.').lower()}."
        )

    def _narrative_summary(self, risk_record: Dict[str, object]) -> str:
        asset = risk_record.get("asset_name")
        service = risk_record.get("business_service")
        cve = risk_record.get("cve")
        actor_text = ", ".join(risk_record.get("threat_actors", [])[:2])
        campaign_text = ", ".join(risk_record.get("campaign_names", [])[:2])
        summary = (
            f"{asset} exposes the {service} service to {cve}. "
            f"The risk is elevated by direct internet reachability, high business impact, and exploit-ready exposure."
        )
        if actor_text or campaign_text:
            summary += f" Active threat intelligence links this issue to {campaign_text or 'current campaigns'}"
            if actor_text:
                summary += f" operated by {actor_text}"
            summary += "."
        if risk_record.get("has_ransomware_threat") or str(risk_record.get("kev_ransomware_use", "")).lower() == "known":
            summary += " The campaign context includes ransomware behavior, which increases likely operational disruption."
        return summary

    def generate_risk_report(self, risk_record: Dict[str, object], rank: int) -> Dict[str, object]:
        control = self.get_remediation_guidance(risk_record)
        threat_context = [
            {"campaign": campaign, "actors": risk_record.get("threat_actors", [])}
            for campaign in risk_record.get("campaign_names", [])
        ]
        return {
            "rank": rank,
            "risk_score": risk_record.get("risk_score"),
            "asset": risk_record.get("asset_name"),
            "asset_type": risk_record.get("asset_type"),
            "asset_environment": risk_record.get("environment"),
            "vulnerability": risk_record.get("vulnerability_name"),
            "cve": risk_record.get("cve"),
            "business_service": risk_record.get("business_service"),
            "business_impact": risk_record.get("business_impact"),
            "threat_intel": risk_record.get("campaign_names", []),
            "threat_actors": risk_record.get("threat_actors", []),
            "threat_context": threat_context,
            "why_it_ranks_here": risk_record.get("plain_english_reason"),
            "summary": self._narrative_summary(risk_record),
            "evidence": risk_record.get("top_factors", []),
            "nist_control_id": control["id"],
            "nist_control_title": control["title"],
            "nist_control_family": control["family"],
            "nist_control_recommendation": control["recommendation"],
            "remediation_summary": self._remediation_summary(control, risk_record),
            "kev_required_action": risk_record.get("kev_required_action", ""),
            "validation_evidence": risk_record.get("hint_validation_evidence", ""),
        }
