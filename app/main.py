from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
import sys

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data_ingestion import load_all_data
from app.rag_service import RAGService
from app.risk_engine import get_top_risks


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Loading datasets and preparing risk report...")
    merged_df, nist_df, metadata = load_all_data()
    rag_service = RAGService(nist_df)
    top_risks = get_top_risks(merged_df, top_n=5)

    generated_reports = []
    for index, risk in enumerate(top_risks, start=1):
        generated_reports.append(rag_service.generate_risk_report(risk, rank=index))

    app.state.report_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_metadata": metadata,
        "top_risks": generated_reports,
    }
    print("Risk report ready.")
    yield


app = FastAPI(title="AI-Powered Cyber Risk Assistant", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/risks")
def get_risks():
    return app.state.report_payload


if not os.path.exists("public"):
    os.makedirs("public")
app.mount("/", StaticFiles(directory="public", html=True), name="public")


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
