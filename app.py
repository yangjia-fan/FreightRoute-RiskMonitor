from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import json

from RouteRisk import run_pipeline, INCIDENTS_OUT, SUMMARY_OUT, HTML_OUT

DEFAULT_RADIUS_KM = 200.0
DEFAULT_HALF_LIFE_DAYS = 14.0

app = FastAPI()

def ensure_build():
    if not INCIDENTS_OUT.exists() or not SUMMARY_OUT.exists() or not HTML_OUT.exists():
        run_pipeline(radius_km=DEFAULT_RADIUS_KM, half_life_days=DEFAULT_HALF_LIFE_DAYS)

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
        return run_pipeline(radius_km=DEFAULT_RADIUS_KM, half_life_days=DEFAULT_HALF_LIFE_DAYS)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))