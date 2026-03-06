from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import json
import requests

from RouteRisk import run_pipeline, INCIDENTS_OUT, SUMMARY_OUT, HTML_OUT

DEFAULT_RADIUS_KM = 200.0
DEFAULT_HALF_LIFE_DAYS = 14.0

GITHUB_INCIDENTS_URL = "https://raw.githubusercontent.com/yangjia-fan/FreightRoute-RiskMonitor/main/dist/incidents.json"
GITHUB_SUMMARY_URL = "https://raw.githubusercontent.com/yangjia-fan/FreightRoute-RiskMonitor/main/dist/summary.json"

app = FastAPI()


def ensure_build():
    if not INCIDENTS_OUT.exists() or not SUMMARY_OUT.exists() or not HTML_OUT.exists():
        run_pipeline(radius_km=DEFAULT_RADIUS_KM, half_life_days=DEFAULT_HALF_LIFE_DAYS)


def load_remote_json(url: str):
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    return r.json()


@app.get("/", response_class=HTMLResponse)
def home():
    ensure_build()
    return HTML_OUT.read_text(encoding="utf-8")


@app.get("/api/incidents")
def api_incidents():
    ensure_build()
    return json.loads(INCIDENTS_OUT.read_text(encoding="utf-8"))


@app.get("/api/summary")
def api_summary():
    ensure_build()
    return json.loads(SUMMARY_OUT.read_text(encoding="utf-8"))


@app.post("/api/refresh")
def api_refresh():
    try:
        # 1) try live pipeline refresh
        result = run_pipeline(
            radius_km=DEFAULT_RADIUS_KM,
            half_life_days=DEFAULT_HALF_LIFE_DAYS
        )
        return {
            "status": "pipeline_success",
            "detail": result
        }

    except Exception as pipeline_error:
        try:
            # 2) fallback: read latest committed JSON from GitHub repo
            incidents = load_remote_json(GITHUB_INCIDENTS_URL)
            summary = load_remote_json(GITHUB_SUMMARY_URL)

            return {
                "status": "pipeline_failed_using_github_repo",
                "pipeline_error": str(pipeline_error),
                "incidents": incidents,
                "summary": summary
            }

        except Exception as github_error:
            # 3) final failure
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "pipeline_failed_and_github_fallback_failed",
                    "pipeline_error": str(pipeline_error),
                    "github_error": str(github_error),
                },
            )