import os
import re
from typing import Dict, List

import chromadb
from chromadb.utils import embedding_functions


def _clean_prose(text: str) -> str:
    cleaned = re.sub(r"\{\{\s*insert:[^}]+\}\}", "", text or "")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _first_sentence(text: str, fallback_words: int = 36) -> str:
    cleaned = _clean_prose(text)
    if not cleaned:
        return ""
    pieces = cleaned.split(". ")
    if pieces and len(pieces[0].split()) >= 8:
        sentence = pieces[0].strip()
        return sentence if sentence.endswith(".") else f"{sentence}."
    words = cleaned.split()
    excerpt = " ".join(words[:fallback_words]).strip()
    return excerpt if excerpt.endswith(".") else f"{excerpt}."


def _brief_recommendation(text: str, max_words: int = 26) -> str:
    cleaned = _clean_prose(text)
    if not cleaned:
        return ""
    first_clause = re.split(r"[.;:]", cleaned)[0].strip()
    words = first_clause.split()
    if len(words) <= max_words:
        result = first_clause
    else:
        result = " ".join(words[:max_words]).strip()
    return result if result.endswith(".") else f"{result}."


class RAGService:
    def __init__(self, nist_df):
        self.nist_records = nist_df.to_dict(orient="records")
        self.collection = None
        self.client = None
        self.embedding_fn = None
        use_embeddings = os.getenv("ENABLE_NIST_EMBEDDINGS", "").strip().lower() in {"1", "true", "yes"}
        if use_embeddings:
            try:
                self.client = chromadb.PersistentClient(path="./chroma_db")
                self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name="all-MiniLM-L6-v2"
                )
                self._rebuild_collection(nist_df)
            except Exception as exc:
                print(f"Falling back to offline lexical NIST retrieval: {exc}")
                self.collection = None
        else:
            print("Using offline lexical NIST retrieval. Set ENABLE_NIST_EMBEDDINGS=1 to enable embedding-backed retrieval.")

    def _rebuild_collection(self, nist_df) -> None:
        collection_name = "nist_controls_v2"
        existing = {collection.name for collection in self.client.list_collections()}
        if collection_name in existing:
            self.client.delete_collection(collection_name)

        self.collection = self.client.create_collection(
            name=collection_name,
            embedding_function=self.embedding_fn,
        )

        ids = nist_df["id"].tolist()
        documents = (
            nist_df["id"].fillna("")
            + " "
            + nist_df["title"].fillna("")
            + " "
            + nist_df["description"].fillna("")
        ).tolist()
        metadatas = [
            {
                "title": row["title"],
                "family": row["family"],
                "group_title": row["group_title"],
                "description": row["description"],
            }
            for _, row in nist_df.iterrows()
        ]

        batch_size = 100
        for start in range(0, len(ids), batch_size):
            end = start + batch_size
            self.collection.add(
                ids=ids[start:end],
                documents=documents[start:end],
                metadatas=metadatas[start:end],
            )

    def _preferred_families(self, risk_record: Dict[str, object]) -> List[str]:
        families = {"RA", "SI"}
        vuln_name = str(risk_record.get("vulnerability_name", "")).lower()
        component = str(risk_record.get("affected_component", "")).lower()
        vendor = str(risk_record.get("vendor_product", "")).lower()
        text = " ".join([vuln_name, component, vendor])

        if any(term in text for term in ["authentication", "account", "session token", "oauth", "access control"]):
            families.update({"AC", "IA"})
        if any(term in text for term in ["incident", "ransomware", "vpn", "citrix", "fortinet"]):
            families.add("IR")
        if any(term in text for term in ["outdated", "unsupported", "runtime", "older version"]):
            families.add("SA")
        if any(term in text for term in ["build", "jenkins", "teamcity", "ci/cd", "secrets"]):
            families.update({"CM", "SC"})

        if risk_record.get("has_ransomware_threat") or str(risk_record.get("kev_ransomware_use", "")).lower() == "known":
            families.add("IR")

        return sorted(families)

    def _tokenize(self, text: str) -> set:
        stop_words = {
            "the",
            "and",
            "for",
            "with",
            "from",
            "this",
            "that",
            "into",
            "system",
            "systems",
            "information",
            "security",
            "organization",
            "organizations",
            "control",
            "controls",
        }
        tokens = set(re.findall(r"[a-z0-9]{3,}", text.lower()))
        return {token for token in tokens if token not in stop_words}

    def _control_boost(self, control_id: str, risk_record: Dict[str, object], query_text: str) -> int:
        text = query_text.lower()
        boost = 0
        if control_id == "AC-2" and any(term in text for term in ["authentication", "account", "session", "access control", "oauth"]):
            boost += 4
        if control_id == "SI-2" and any(term in text for term in ["rce", "exploit", "patch", "vulnerability", "injection", "bypass"]):
            boost += 4
        if control_id == "RA-5" and any(term in text for term in ["scan", "monitor", "exposure", "internet-facing", "detection"]):
            boost += 4
        if control_id == "IR-4" and (
            risk_record.get("has_ransomware_threat") or str(risk_record.get("kev_ransomware_use", "")).lower() == "known"
        ):
            boost += 4
        if control_id == "SA-22" and any(term in text for term in ["outdated", "older version", "unsupported", "runtime"]):
            boost += 4
        return boost

    def _lexical_fallback(self, query_text: str, preferred_families: List[str], risk_record: Dict[str, object]) -> Dict[str, str]:
        query_tokens = self._tokenize(query_text)
        shortlist = [
            record for record in self.nist_records if record.get("family") in preferred_families
        ] or self.nist_records

        best_record = shortlist[0]
        best_score = -1
        for record in shortlist:
            record_text = " ".join(
                [
                    str(record.get("id", "")),
                    str(record.get("title", "")),
                    str(record.get("description", "")),
                    str(record.get("group_title", "")),
                ]
            )
            record_tokens = self._tokenize(record_text)
            score = len(query_tokens & record_tokens)
            score += self._control_boost(str(record.get("id")), risk_record, query_text)
            if score > best_score:
                best_score = score
                best_record = record

        return {
            "id": best_record["id"],
            "title": best_record["title"],
            "family": best_record["family"],
            "description": best_record["description"],
            "recommendation": _brief_recommendation(best_record["description"]),
        }

    def get_remediation_guidance(self, risk_record: Dict[str, object]) -> Dict[str, str]:
        preferred_families = self._preferred_families(risk_record)
        threat_context = " ".join(risk_record.get("threat_summaries", [])[:2])
        query_text = " ".join(
            [
                str(risk_record.get("vulnerability_name", "")),
                str(risk_record.get("affected_component", "")),
                str(risk_record.get("asset_type", "")),
                str(risk_record.get("business_service", "")),
                str(risk_record.get("remediation_hint", "")),
                threat_context,
            ]
        ).strip()

        if self.collection is None:
            return self._lexical_fallback(query_text, preferred_families, risk_record)

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=3,
                where={"family": {"$in": preferred_families}},
            )

            if not results["ids"][0]:
                results = self.collection.query(query_texts=[query_text], n_results=3)

            best_control_id = results["ids"][0][0]
            metadata = results["metadatas"][0][0]
            description = metadata["description"]

            return {
                "id": best_control_id,
                "title": metadata["title"],
                "family": metadata["family"],
                "description": description,
                "recommendation": _brief_recommendation(description),
            }
        except Exception:
            return self._lexical_fallback(query_text, preferred_families, risk_record)

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
            {
                "campaign": campaign,
                "actors": risk_record.get("threat_actors", []),
            }
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
