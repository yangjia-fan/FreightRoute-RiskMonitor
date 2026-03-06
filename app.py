from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import json
import time

from RouteRisk import INCIDENTS_OUT, SUMMARY_OUT, HTML_OUT

DEFAULT_RADIUS_KM = 200.0
DEFAULT_HALF_LIFE_DAYS = 14.0
REFRESH_SECONDS = 300  # 5 minutes

app = FastAPI()

_last_load = 0.0
_cache = {
    "html": None,
    "incidents": None,
    "summary": None,
}


def reload_files_if_needed(force: bool = False) -> None:
    global _last_load

    if not force and (time.time() - _last_load < REFRESH_SECONDS):
        return

    _cache["html"] = HTML_OUT.read_text(encoding="utf-8")
    _cache["incidents"] = json.loads(INCIDENTS_OUT.read_text(encoding="utf-8"))
    _cache["summary"] = json.loads(SUMMARY_OUT.read_text(encoding="utf-8"))
    _last_load = time.time()

    print("Reloaded static files from dist/")


@app.on_event("startup")
def startup_load() -> None:
    reload_files_if_needed(force=True)


@app.get("/", response_class=HTMLResponse)
def home():
    reload_files_if_needed()
    return _cache["html"]


@app.get("/api/incidents")
def api_incidents():
    reload_files_if_needed()
    return _cache["incidents"]


@app.get("/api/summary")
def api_summary():
    reload_files_if_needed()
    return _cache["summary"]
