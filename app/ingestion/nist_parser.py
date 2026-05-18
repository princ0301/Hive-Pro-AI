import json
from typing import Iterable, List

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

    return pd.DataFrame(nist_controls).drop_duplicates(subset=["id"])
