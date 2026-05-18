# AI-Powered Cyber Risk Assistant

This project is a submission for the `AI Intern - Take-Home Assignment` to build an explainable cyber risk assistant for TawasolPay.

The application ingests the provided structured datasets, correlates them with the `CISA Known Exploited Vulnerabilities (KEV)` catalog, ranks the most important risks using assignment-aligned factors, and retrieves remediation guidance from the `NIST SP 800-53 Rev. 5` control catalog.

## What the system does

- Ingests `assets.csv`, `vulnerabilities.csv`, `threat_intelligence.csv`, `business_services.csv`, `remediation_guidance.csv`, `kev.json`, `nist_800_53.json`, and `synthetic_threat_report.md`
- Scores every `asset + vulnerability` record using more than CVSS alone
- Ranks the `top 5 risks`
- Retrieves the most relevant NIST control for each risk
- Produces a readable analyst-style risk entry with:
  - asset
  - vulnerability
  - matched threat intel
  - business service at risk
  - why it ranks here
  - retrieved NIST remediation guidance

## Risk-ranking methodology

The scoring model combines the factors called out in the assignment:

- `Internet exposure`
- `Active exploitation / exploit availability`
- `Threat actor and campaign matches`
- `Ransomware association`
- `Business criticality and revenue impact`
- `Customer-facing exposure`
- `Compliance scope`
- `Missing compensating controls` such as missing EDR
- `Remediation delay` using days open and patch availability

The resulting score is intentionally explainable. Each risk record includes the top scoring factors and the reason each factor contributed to the final rank.

## Retrieval approach

The NIST control catalog is parsed from the real `NIST SP 800-53 Rev. 5` OSCAL JSON and stored in a retrieval-friendly structure.

- Default mode: the app uses `offline lexical retrieval`, which keeps the project runnable in restricted environments.
- Optional semantic mode: if `ENABLE_NIST_EMBEDDINGS=1` is set and the embedding model is available, the app uses `ChromaDB + sentence-transformers` for embedding-backed retrieval.

This keeps the demo reliable for reviewers while still supporting the intended structured-data-vs-retrieval split.

## Project structure

```text
app/
  __init__.py         # package marker for module and direct-script execution
  data_ingestion.py   # data loading, joins, KEV/threat enrichment, threat-report ingestion
  risk_engine.py      # explainable risk scoring
  rag_service.py      # NIST retrieval and readable report generation
  main.py             # FastAPI app
public/
  index.html          # human-readable frontend
data/
  ...                 # provided datasets + retrieved public reference files
```

## Running locally

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Start the app:

   ```bash
   python -m app.main
   ```

   You can also run:

   ```bash
   python .\app\main.py
   ```

3. Open:

   ```text
   http://localhost:8000
   ```

### Optional embedding-backed retrieval

If you want to use semantic retrieval for NIST controls instead of the offline lexical fallback:

```bash
set ENABLE_NIST_EMBEDDINGS=1
python -m app.main
```

This requires the embedding model to be available locally or downloadable from the execution environment.

## Data refresh

`get_data.py` is included as a helper to refresh public reference files such as `kev.json`. The repository already includes the data needed to run the submission locally.

## Supporting question 1 - The data split

### What data did you embed and why?

I treated the `NIST SP 800-53 Rev. 5` control catalog as retrieval data because it is long-form, prose-heavy, and semantically matched rather than joined by a strict key. A vulnerability like `CitrixBleed` or `Fortinet auth bypass` does not map cleanly to a single deterministic control ID in the way a CVE maps to a KEV record, so the control text is the right place to use retrieval.

The app supports embedding-backed retrieval with `ChromaDB + sentence-transformers` when that mode is enabled. For restricted or offline review environments, it falls back to lexical retrieval over the same NIST source text so the system remains runnable.

### What data did you query as structured records and why?

I queried `assets`, `vulnerabilities`, `business services`, `threat intelligence`, and `CISA KEV` as structured records because they are relational datasets with explicit fields that need deterministic joins and scoring. Risk ranking depends on exact facts such as `internet_exposed = Yes`, `cvss = 9.8`, `knownRansomwareCampaignUse = Known`, `EDR installed = No`, or `business service = Payment Processing`, and those are better handled with Pandas than with an LLM.

## Supporting question 2 - Where it goes wrong

### Three specific ways the system can produce an incorrect or misleading output

1. If the `threat_intelligence.csv` file uses a different CVE, alias, or campaign naming convention than the vulnerability dataset, the system may miss a threat match and under-rank the risk.
   Mitigation: I currently do exact CVE correlation and threat-report term matching. The next improvement would be alias tables and fuzzy normalization for actor and campaign names.

2. If the KEV catalog does not yet include a vulnerability that is actively exploited in the wild, the system will not award KEV-specific risk points even though real-world exploitation may already be happening.
   Mitigation: I separated `exploit_available` and `direct threat intel match` from `KEV presence`, so a vulnerability can still rank highly without KEV. The next step would be adding EPSS or another exploit-likelihood signal.

3. If the execution environment is offline and embedding retrieval is not available, lexical control matching may retrieve a good but not optimal NIST control for edge cases with ambiguous wording.
   Mitigation: the app preserves the same real NIST source text in both modes and constrains retrieval by likely control families such as `RA`, `SI`, `IR`, `AC`, and `SA`. In a production version I would cache the embedding model with the deployment image to avoid this downgrade.

## Supporting question 3 - One thing I would change

If I had another day, the single most important improvement would be to move the risk engine from a static weighted heuristic to a calibration layer that combines `EPSS`, KEV recency, and environment-specific blast radius into a more defensible probability-of-exploitation score. The current scoring is explainable and assignment-aligned, but it is still a hand-tuned model; the next version should preserve explainability while improving calibration.

## Notes on deployment

The codebase is ready to deploy to a small FastAPI-compatible host such as `Render`, `Railway`, or `Fly.io`. The local submission package includes everything needed to run the app; the remaining deployment step is publishing it to a public URL in the target hosting account.
