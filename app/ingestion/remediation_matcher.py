from typing import Tuple

import pandas as pd

from app.ingestion.common import tokenize


def match_remediation_hint(row: pd.Series, hints_df: pd.DataFrame) -> Tuple[str, str, str, str]:
    context = " ".join(
        [
            str(row.get("vulnerability_name", "")),
            str(row.get("affected_component", "")),
            str(row.get("asset_type", "")),
            str(row.get("vendor_product", "")),
            str(row.get("cve", "")),
        ]
    )
    context_tokens = tokenize(context)

    best_score = 0
    best_match = None
    for _, hint_row in hints_df.iterrows():
        hint_tokens = tokenize(str(hint_row.get("finding_type", "")))
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
