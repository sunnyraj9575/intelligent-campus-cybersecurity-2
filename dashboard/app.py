"""
FastAPI Server & Security Operations Center (SOC) Web Dashboard.
Serves interactive cyber threat analytics, real-time telemetry streaming, and REST API endpoints.
"""

import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.config_loader import get_project_root, load_config
from src.detector import CampusThreatDetector
from src.incident_advisor import IncidentAdvisor

app = FastAPI(
    title="Intelligent Campus Cyber Threat Detection System",
    description="Supervised Machine Learning Cyber Defense & Intrusion Detection System",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = get_project_root()
detector: Optional[CampusThreatDetector] = None

# Static & Template paths
static_dir = PROJECT_ROOT / "dashboard" / "static"
templates_dir = PROJECT_ROOT / "dashboard" / "templates"
static_dir.mkdir(parents=True, exist_ok=True)
templates_dir.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def get_detector() -> CampusThreatDetector:
    global detector
    if detector is None:
        detector = CampusThreatDetector()
    return detector


class FlowInput(BaseModel):
    duration: float = Field(0.05, description="Flow duration in seconds")
    protocol_type: str = Field("TCP", description="Protocol: TCP, UDP, or ICMP")
    service: str = Field("HTTPS", description="Service: HTTP, HTTPS, SSH, DNS, FTP, etc.")
    conn_state: str = Field("SF", description="Connection state: SF, S0, REJ, RSTO")
    src_bytes: int = Field(450, description="Source payload bytes")
    dst_bytes: int = Field(1200, description="Destination payload bytes")
    src_pkts: int = Field(12, description="Source packets count")
    dst_pkts: int = Field(10, description="Destination packets count")
    pkt_rate: float = Field(440.0, description="Packets per second")
    byte_rate: float = Field(33000.0, description="Bytes per second")
    avg_pkt_size: float = Field(75.0, description="Average packet size")
    failed_logins: int = Field(0, description="Number of failed logins")
    port_entropy: float = Field(0.15, description="Port entropy score (0 to 1)")
    payload_entropy: float = Field(4.2, description="Payload byte entropy (0 to 8)")
    syn_flag_count: int = Field(1, description="Count of SYN flags")
    rst_flag_count: int = Field(0, description="Count of RST flags")
    ack_flag_count: int = Field(9, description="Count of ACK flags")
    src_subnet: str = Field("dorms", description="dorms, labs, admin, server_farm, guest_wifi, external")
    dst_subnet: str = Field("server_farm", description="server_farm, admin, labs, dorms, external")
    is_guest_network: int = Field(0, description="1 if guest Wi-Fi, else 0")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the Cyber Defense Operations Center HTML interface."""
    index_file = templates_dir / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Dashboard index.html not found.</h1>", status_code=404)
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/status")
async def get_system_status():
    """System health and model configuration status."""
    d = get_detector()
    return {
        "status": "ONLINE",
        "system_name": "Campus Cyber Threat Detection System",
        "model_type": d.model.__class__.__name__,
        "classes": d.classes,
        "features_loaded": len(d.preprocessor.feature_columns),
    }


@app.get("/api/metrics")
async def get_metrics():
    """Return stored model benchmark evaluation results."""
    summary_path = PROJECT_ROOT / "models" / "saved" / "metrics_summary.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Metrics summary not found. Train model first.")
    with open(summary_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.post("/api/predict")
async def predict_single(flow: FlowInput):
    """Classify a single network flow."""
    d = get_detector()
    result = d.detect_single(flow.model_dump())
    return result


@app.post("/api/batch-predict")
async def predict_batch(file: UploadFile = File(...)):
    """Upload CSV log file for threat batch detection."""
    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")

    d = get_detector()
    classified_df = d.detect_batch(df)

    # Calculate summary metrics
    threat_counts = classified_df["predicted_threat"].value_counts().to_dict()
    total = len(classified_df)
    threats_total = int(classified_df["is_threat"].sum())

    sample_records = classified_df.head(100).to_dict(orient="records")

    return {
        "total_records": total,
        "threats_detected": threats_total,
        "threat_distribution": threat_counts,
        "records": sample_records,
    }


@app.get("/api/simulate-stream")
async def simulate_stream(count: int = 6):
    """Simulate streaming campus traffic events with live ML predictions."""
    d = get_detector()
    events = []
    for _ in range(max(1, min(count, 50))):
        events.append(d.simulate_stream_event())
    return {"events": events}


@app.get("/api/mitigation/{threat_label}")
async def get_mitigation_plan(threat_label: str):
    """Retrieve tactical mitigation plan for a threat class."""
    advisory = IncidentAdvisor.get_advisory(threat_label)
    return advisory


@app.get("/api/subnet-overview")
async def get_subnet_overview():
    """Return campus network topology and subnet threat profile."""
    config = load_config()
    return config.get("subnets", {})


def run_server(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    uvicorn.run("dashboard.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    run_server()
