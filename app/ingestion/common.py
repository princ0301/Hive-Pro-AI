import re
from typing import Iterable, List

import pandas as pd


def safe_number(frame: pd.DataFrame, column: str) -> None:
    if column in frame.columns:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")


def unique_list(values: Iterable[object]) -> List[str]:
    cleaned = []
    for value in values:
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def best_confidence(values: Iterable[object]) -> str:
    ranking = {"low": 1, "medium": 2, "high": 3}
    best = "Unknown"
    best_score = 0
    for value in values:
        score = ranking.get(str(value).strip().lower(), 0)
        if score > best_score:
            best_score = score
            best = str(value).strip().title()
    return best


def tokenize(text: str) -> set:
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
