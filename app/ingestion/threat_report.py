from typing import List

import pandas as pd

from app.ingestion.common import unique_list


def extract_threat_report_terms(report_text: str, row: pd.Series) -> List[str]:
    matches = []
    search_terms = unique_list(
        [row.get("cve")] + row.get("campaign_names", []) + row.get("threat_actors", [])
    )
    report_lower = report_text.lower()
    for term in search_terms:
        if term and str(term).lower() in report_lower:
            matches.append(str(term))
    return matches
