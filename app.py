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
        result = run_pipeline(
            radius_km=DEFAULT_RADIUS_KM,
            half_life_days=DEFAULT_HALF_LIFE_DAYS
        )

        print("Refresh pipeline ran successfully")

    except Exception as pipeline_error:

        print("Pipeline failed, falling back to GitHub:", pipeline_error)

        try:
            r = requests.get(
                "https://raw.githubusercontent.com/yangjia-fan/FreightRoute-RiskMonitor/main/dist/summary.json",
                timeout=20
            )
            r.raise_for_status()
            result = r.json()

        except Exception as github_error:
            raise HTTPException(
                status_code=500,
                detail={
                    "pipeline_error": str(pipeline_error),
                    "github_error": str(github_error),
                },
            )

    # Always print what timestamp we ended up with
    generated = result.get("generated_utc")
    print("Refresh endpoint returning generated_utc:", generated)

    return {
        "generated_utc": generated,
        "n": result.get("n"),
        "status": "ok"
    }