import json
import os
import urllib.request


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


def _download_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def _write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def download_kev(data_dir: str = "data") -> None:
    kev_data = _download_json(KEV_URL)
    if "vulnerabilities" not in kev_data:
        raise ValueError("Downloaded KEV feed does not contain a vulnerabilities list.")
    _write_json(os.path.join(data_dir, "kev.json"), kev_data)
    print("Downloaded CISA KEV JSON -> data/kev.json")


def download_nist(data_dir: str = "data") -> None:
    nist_data = _download_json(NIST_OSCAL_URL)
    catalog = nist_data.get("catalog", {})
    if not catalog or "groups" not in catalog:
        raise ValueError("Downloaded NIST file is not a valid OSCAL catalog JSON document.")
    _write_json(os.path.join(data_dir, "nist_800_53.json"), nist_data)
    print("Downloaded NIST OSCAL JSON -> data/nist_800_53.json")


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    try:
        download_kev()
        download_nist()
    except Exception as exc:
        print(f"Error: {exc}")
