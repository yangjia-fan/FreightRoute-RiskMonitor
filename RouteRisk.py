#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socketserver
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

API_URL = "https://cd.royalnavy.mod.uk/api/ukmto/all"
REFERER = "https://www.ukmto.org/recent-incidents"

DIST_DIR = Path("dist")
INCIDENTS_OUT = DIST_DIR / "incidents.json"
HTML_OUT = DIST_DIR / "index.html"
SUMMARY_OUT = DIST_DIR / "summary.json"

import re
from typing import Any, Dict, List, Tuple, Optional

# ---------------------------
# Severity Factor Calculation
# ---------------------------

# Base patterns: weights reflect "how bad if true"
# Use regex with word boundaries and simple variants.
BASE_PATTERNS: List[Dict[str, Any]] = [
    {"re": r"\b(hijack|hijacked|seized)\b", "w": 8, "tags": ["piracy"]},
    {"re": r"\b(boarded|boarding)\b", "w": 6, "tags": ["piracy"]},
    {"re": r"\b(kidnap|abduct|hostage)\b", "w": 8, "tags": ["piracy", "casualty"]},

    {"re": r"\b(missile|rocket|projectile)\b", "w": 7, "tags": ["weapon"]},
    {"re": r"\b(drone|uav|uas)\b", "w": 6, "tags": ["weapon"]},
    {"re": r"\b(usv)\b", "w": 7, "tags": ["weapon"]},
    {"re": r"\b(small arms|gunfire|shots fired)\b", "w": 4, "tags": ["kinetic"]},
    {"re": r"\b(attack|attacked|assault)\b", "w": 6, "tags": ["attack"]},

    {"re": r"\b(explosion|exploded|blast)\b", "w": 6, "tags": ["effect"]},
    {"re": r"\b(struck|hit|impacted)\b", "w": 5, "tags": ["effect"]},

    {"re": r"\b(fire|firefighting)\b", "w": 4, "tags": ["damage"]},
    {"re": r"\b(damage|damaged|flooding|breach|hull)\b", "w": 4, "tags": ["damage"]},

    {"re": r"\b(injury|injuries|wounded|fatalit(y|ies)|killed|dead)\b", "w": 6, "tags": ["casualty"]},
    {"re": r"\b(evacuated|abandoned ship|distress|mayday)\b", "w": 4, "tags": ["response"]},

    {"re": r"\b(jamming|interference|spoofing|gnss)\b", "w": 3, "tags": ["ew"]},
    {"re": r"\b(ais)\b", "w": 2, "tags": ["ew"]},

    {"re": r"\b(suspicious|approached|shadowed|followed)\b", "w": 2, "tags": ["suspicious"]},
]

# Strong "not serious / resolved" signals
NEGATION_PATTERNS = [
    r"\b(no damage|no injuries|crew (are|is) safe|all crew safe)\b",
    r"\b(false alarm|hoax|mistaken|misidentified|unfounded)\b",
    r"\b(stand[- ]down|stood down|cancelled)\b",
]

# Uncertainty / attempt / alleged language => discount severity
UNCERTAINTY_PATTERNS = [
    r"\b(suspected|reported|alleged|possibly|probable|unconfirmed)\b",
]
ATTEMPT_PATTERNS = [
    r"\b(attempted|attempt|unsuccessful|thwarted|repelled|prevented)\b",
]

# Escalators that push severity up if present (on top of base hits)
ESCALATORS: List[Dict[str, Any]] = [
    {"re": r"\b(sank|sinking|taking on water)\b", "add": 4, "tags": ["catastrophic"]},
    {"re": r"\b(on fire|major fire|engine room fire)\b", "add": 2, "tags": ["major_damage"]},
    {"re": r"\b(explosion|blast)\b", "add": 1, "tags": ["escalated"]},
    {"re": r"\b(injuries|fatalit(y|ies)|killed|dead)\b", "add": 2, "tags": ["escalated"]},
]

# Optional: incorporate UKMTO incidentTypeLevel as a prior.
# You MUST calibrate this based on what values you actually see (string? int?).
# This mapping is intentionally conservative.
LEVEL_PRIOR = {
    "1": 0.5,
    "2": 1.5,
    "3": 2.5,
    "4": 3.5,
    "5": 4.5,
}

def _compile_once():
    """Compile regex once (micro-optimization + cleaner)."""
    compiled = []
    for p in BASE_PATTERNS:
        compiled.append({**p, "rx": re.compile(p["re"], flags=re.IGNORECASE)})
    neg = [re.compile(x, flags=re.IGNORECASE) for x in NEGATION_PATTERNS]
    unc = [re.compile(x, flags=re.IGNORECASE) for x in UNCERTAINTY_PATTERNS]
    att = [re.compile(x, flags=re.IGNORECASE) for x in ATTEMPT_PATTERNS]
    esc = []
    for e in ESCALATORS:
        esc.append({**e, "rx": re.compile(e["re"], flags=re.IGNORECASE)})
    return compiled, neg, unc, att, esc

_COMPILED_BASE, _COMPILED_NEG, _COMPILED_UNC, _COMPILED_ATT, _COMPILED_ESC = _compile_once()

def severity(
    text: str,
    incident_type_level: Optional[Any] = None,
) -> Tuple[float, List[str]]:
    """
    Deterministic severity score in [0, 20].
    Uses:
      - base keyword hits (regex w/ boundaries)
      - uncertainty / attempt discounts
      - explicit negation discounts
      - small escalators (sank/injuries/etc.)
      - optional UKMTO type-level prior
    """
    t = (text or "").strip()
    if not t:
        # If no text, fall back to level prior only (if provided)
        base = 0.0
    else:
        base = 0.0

    tags = set()

    # Base hits
    for p in _COMPILED_BASE:
        if p["rx"].search(t):
            base += float(p["w"])
            for tg in p["tags"]:
                tags.add(tg)

    # Escalators (additive)
    for e in _COMPILED_ESC:
        if e["rx"].search(t):
            base += float(e["add"])
            for tg in e["tags"]:
                tags.add(tg)

    # Discounts
    neg_hits = sum(1 for rx in _COMPILED_NEG if rx.search(t))
    unc_hits = sum(1 for rx in _COMPILED_UNC if rx.search(t))
    att_hits = sum(1 for rx in _COMPILED_ATT if rx.search(t))

    # Negation: strong downward pull (but not instantly to 0)
    if neg_hits:
        base -= 2.0 * neg_hits
        tags.add("deescalated")

    # Uncertainty: mild discount
    if unc_hits:
        base *= 0.85
        tags.add("uncertain")

    # Attempt/thwarted: stronger discount
    if att_hits:
        base *= 0.75
        tags.add("attempted")

    # Level prior (optional): add a small prior boost
    lvl = None
    if incident_type_level is not None:
        lvl = str(incident_type_level).strip()
        if lvl in LEVEL_PRIOR:
            base += LEVEL_PRIOR[lvl]
            tags.add(f"level_{lvl}")

    # Clamp
    score = max(0.0, min(20.0, float(base)))
    return score, sorted(tags)

def classify(tags: List[str]) -> str:
    s = set(tags)
    if "piracy" in s:
        return "Piracy/Boarding"
    if "weapon" in s or "attack" in s or "kinetic" in s:
        return "Kinetic Attack"
    if "ew" in s:
        return "EW / GNSS"
    if "suspicious" in s:
        return "Suspicious Activity"
    return "Other"


# ---------------------------
# Fetch + build
# ---------------------------
def fetch_incidents() -> List[Dict[str, Any]]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Referer": REFERER,
        "Origin": "https://www.ukmto.org",
    }
    r = requests.get(API_URL, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise ValueError("API did not return a list")
    return data


def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def enrich(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    NOTE: We do NOT bake lane distance / proximity / contribution here anymore.
    Those are re-computed in the browser based on the selected lane.
    """
    now = datetime.now(timezone.utc)
    out: List[Dict[str, Any]] = []

    for x in incidents:
        dt = parse_dt(x["utcDateOfIncident"])
        age_days = max(0.0, (now - dt).total_seconds() / 86400.0)

        lat = float(x["locationLatitude"])
        lon = float(x["locationLongitude"])

        text = x.get("otherDetails", "") or ""
        sev, tags = severity(text, incident_type_level=x.get("incidentTypeLevel"))
        category = classify(tags)

        out.append(
            {
                "id": f'{x.get("incidentIssuer","UKMTO")}-{x.get("incidentNumber")}',
                "incidentNumber": x.get("incidentNumber"),
                "incidentTypeName": x.get("incidentTypeName"),
                "incidentTypeLevel": x.get("incidentTypeLevel"),
                "pinColour": x.get("pinColour"),
                "place": x.get("place"),
                "region": x.get("region"),
                "published_utc": x.get("utcDateCreated"),
                "incident_utc": x.get("utcDateOfIncident"),
                "lat": lat,
                "lon": lon,
                "otherDetails": text,
                "severity": sev,
                "tags": tags,
                "category": category,
                "age_days": age_days,
            }
        )

    # sort by recency: newest first (smallest age_days)
    out.sort(key=lambda z: float(z.get("age_days", 1e9)))
    return out


# ---------------------------
# Build artifacts
# ---------------------------
def write_artifacts(enriched: List[Dict[str, Any]], radius_km: float, half_life_days: float) -> None:
    DIST_DIR.mkdir(exist_ok=True)

    INCIDENTS_OUT.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
    HTML_OUT.write_text(build_html(radius_km=radius_km, half_life_days=half_life_days), encoding="utf-8")

    SUMMARY_OUT.write_text(
        json.dumps(
            {
                "generated_utc": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "n": len(enriched),
                "params": {"radius_km": radius_km, "half_life_days": half_life_days},
                "top5_by_severity": [
                    {
                        "id": x["id"],
                        "incident_utc": x["incident_utc"],
                        "type": x["incidentTypeName"],
                        "place": x["place"],
                        "severity": x["severity"],
                    }
                    for x in enriched[:5]
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def build_html(radius_km: float, half_life_days: float) -> str:
    # IMPORTANT:
    # Refresh button calls POST /api/refresh on the local server, which re-runs the pipeline
    # and rewrites dist/incidents.json + dist/summary.json.
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>UKMTO Route Risk Monitor</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin=""/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>

<style>
  :root{{
    --bg:#0b0f14;
    --panel:#0f1620;
    --panel2:#0c121a;
    --text:#e6edf3;
    --muted:#9aa4af;
    --border:rgba(255,255,255,0.10);
  }}
  body{{ margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:var(--bg); color:var(--text); }}
  #app{{ display:grid; grid-template-columns:318px 1fr; height:100vh; }}
  #sidebar{{ border-right:1px solid var(--border); padding:14px; overflow:auto; background:var(--panel); }}
  #map{{ height:100vh; }}

  .row{{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .kpi{{ border:1px solid var(--border); background:var(--panel2); border-radius:12px; padding:10px 12px; min-width:180px; }}
  .kpi .label{{ font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; }}
  .kpi .value{{ font-size:22px; font-weight:700; }}

  .muted{{ color:var(--muted); font-size:12px; line-height:1.4; }}
  label{{ font-size:12px; color:var(--muted); display:block; margin-bottom:6px; }}

  button, select{{
    background:var(--panel2);
    color:var(--text);
    border:1px solid var(--border);
    border-radius:10px;
    padding:8px 10px;
  }}
  button{{ cursor:pointer; }}
  button:hover{{ filter:brightness(1.1); }}
  button:disabled{{ opacity:0.6; cursor:not-allowed; }}

  .controls{{ margin-top:12px; display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap; }}
  .checkpanel{{
    display:flex;
    flex-direction:column;
    gap:6px;
    max-height:220px;
    overflow:auto;
    padding:10px;
    border:1px solid var(--border);
    border-radius:12px;
    background:var(--panel2);
    min-width:260px;
  }}
  .checkrow{{
    display:flex;
    align-items:center;
    gap:8px;
    cursor:pointer;
    user-select:none;
    font-size:13px;
    color:var(--text);
  }}
  .checkrow input{{ cursor:pointer; }}
  .dot{{ width:10px; height:10px; border-radius:999px; display:inline-block; border:1px solid rgba(255,255,255,0.25); }}

  .pill{{
    display:inline-block;
    padding:3px 8px;
    border:1px solid var(--border);
    border-radius:999px;
    font-size:12px;
    color:var(--text);
    background:rgba(255,255,255,0.04);
  }}

  .incident{{
    border:1px solid var(--border);
    background:var(--panel2);
    border-radius:12px;
    padding:10px;
    margin-top:10px;
  }}
  .incident h4{{ margin:0 0 6px 0; font-size:14px; }}
  .incident .meta{{ font-size:12px; color:var(--muted); display:flex; gap:8px; flex-wrap:wrap; }}
  .incident .desc{{ font-size:12px; color:var(--text); margin-top:8px; white-space:pre-wrap; opacity:0.95; }}

  .headerRow{{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px; }}
  .headerRight{{ display:flex; flex-direction:column; align-items:flex-end; gap:6px; }}
  .metaLine{{
    font-size:10px;
    color:var(--muted);
    display:flex;
    gap:5px;
    align-items:baseline;
  }}

  .metaLine .val{{
    color:var(--text);
    font-weight:600;
    font-size:10px;
  }}

  /* Center modal */
  .modalOverlay{{
    position:fixed;
    inset:0;
    background:rgba(0,0,0,0.55);
    display:none;
    align-items:center;
    justify-content:center;
    z-index:99999;
    padding:24px;
  }}
  .modalOverlay.open{{ display:flex; }}
  .modalCard{{
    width:min(680px, calc(100vw - 48px));
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:16px;
    box-shadow:0 18px 60px rgba(0,0,0,0.5);
    padding:14px 14px 12px 14px;
  }}
  .modalHeader{{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:10px; }}
  .modalTitle{{ font-size:14px; font-weight:700; color:var(--text); }}
  .modalClose{{ background:transparent; border:1px solid var(--border); color:var(--text); border-radius:10px; padding:6px 10px; cursor:pointer; }}
  .modalBody{{ color:var(--text); font-size:12px; line-height:1.45; }}
  .modalBody code{{ background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.10); padding:1px 6px; border-radius:8px; }}

  /* dark popup */
  .leaflet-popup-content-wrapper, .leaflet-popup-tip{{
    background:#0f1620;
    color:#e6edf3;
    border:1px solid rgba(255,255,255,0.10);
  }}
  .leaflet-control-attribution{{
    background:rgba(0,0,0,0.4);
    color:#cbd5e1;
  }}
  .leaflet-control-attribution a{{ color:#cbd5e1; }}
</style>
</head>

<body>
<div id="app">
  <div id="sidebar">
    <h3 style="margin:0 0 6px 0;">UKMTO Route Risk Monitor</h3>

    <div class="controls" style="margin-top:6px;">
      <div style="flex:1 1 auto;">
        <label>Route</label>
        <select id="laneSelect"></select>
        <div class="muted" style="margin-top:6px;">
          Different Route → Different <b>Proximity</b> to Incidents → Different Risk Index
        </div>
      </div>
      <!--
      <div>
        <label>&nbsp;</label>
        <button id="resetViewBtn" type="button" title="Fit view to visible markers + lane">Reset view</button>
      </div>
      -->
    </div>

    <h3 style="margin: 14px 0 8px;">Metrics</h3>
    <div class="row">
      <div class="kpi">
        <div class="label">
          Risk Index
          <button id="riskInfoBtn" class="modalClose" type="button" style="padding:2px 8px;">?</button>
        </div>
        <div class="value" id="riskFactor">—</div>
        <div class="muted">Σ(severity × recency × proximity)</div>
      </div>

      <div class="kpi">
        <div class="label">Incidents (filtered)</div>
        <div class="value" id="nIncidents">—</div>
      </div>
    </div>

    <div class="controls">
      <div style="flex:1 1 auto;">
        <label>Incident type filter</label>
        <div id="categoryChecks" class="checkpanel"></div>
      </div>
    </div>

    <div class="headerRow" style="margin: 14px 0 8px;">
      <h3 style="margin:0;">Incidents</h3>

      <div class="headerRight">
        <button id="refreshBtn" type="button" title="Re-run the Python refresh on the local server">Refresh</button>

        <div class="metaLine">
          <span>Last update:</span>
          <span id="lastUpdated" class="val">—</span>
        </div>

        <div class="metaLine">
          <span>Status:</span>
          <span id="statusText" class="val">—</span>
        </div>
      </div>
    </div>

    <div id="incidentsList"></div>
    <div style="margin-top:16px; padding-top:8px; border-top:1px solid var(--border); font-size:12px; color:var(--muted);">
      View project on 
      <a href="https://github.com/yangjia-fan/FreightRoute-RiskMonitor"
        target="_blank"
        style="color:inherit; text-decoration:underline;">
        GitHub
      </a>
    </div>
  </div>

  <div id="map"></div>
</div>

<!-- Center modal -->
<div id="riskModal" class="modalOverlay" aria-hidden="true">
  <div class="modalCard" role="dialog" aria-modal="true" aria-labelledby="riskModalTitle">
    <div class="modalHeader">
      <div id="riskModalTitle" class="modalTitle">Risk Index definition</div>
      <button id="riskModalClose" class="modalClose" type="button">Close</button>
    </div>
    <div class="modalBody">
      <b>Risk Index (0–100)</b><br><br>

      The Risk Index estimates the relative operational risk for vessels travelling
      along the selected route. It aggregates nearby maritime security incidents and
      weights them by severity, recency, and proximity to the route.<br><br>

      <b>Step 1 — Raw Risk</b><br>
      Each incident contributes a score based on three components:<br><br>

      <code>RawRisk = Σ (severity × recency × proximity)</code><br><br>

      <b>severity</b><br>
      The severity score is derived from the incident description using a deterministic keyword and context scoring rule. 
      Terms associated with weapons, attacks, damage, or casualties increase the score, while language indicating 
      uncertainty or lack of harm (e.g., “no injuries”, “suspected”, “attempted”) reduces it.<br><br>

      Interpretation of the scale:<br>
      • Suspicious activity or approach → low severity<br>
      • Boarding attempts or hostile interaction → moderate severity<br>
      • Confirmed attacks involving weapons, explosions, or casualties → high severity<br><br>

      The score is capped at <b>20</b> to prevent a single incident from dominating the overall risk calculation.

      <b>recency</b><br>
      Recent incidents carry more weight than older ones using exponential decay:<br><br>

      <code>recency = 0.5^(age_days / half_life_days)</code><br><br>

      The parameter <code>half_life_days</code> controls how quickly incidents lose influence.
      For example, if half-life = 7 days, an incident contributes half as much after one week.<br><br>

      <b>proximity</b><br>
      Incidents closer to the shipping route are more relevant:<br><br>

      <code>proximity = exp(−distance_to_lane_km / radius_km)</code><br><br>

      The parameter <code>radius_km</code> determines the spatial decay.
      Incidents directly on the route receive full weight, while distant events contribute less.<br><br>

      <b>Step 2 — Convert Raw Risk to Index</b><br>

      RawRisk is converted into a bounded index between 0 and 100:<br><br>

      <code>RiskIndex = 100 × (1 − exp(−RawRisk / 15))</code><br><br>

      This transformation prevents the score from increasing indefinitely when many
      incidents occur. Instead, the index saturates as risk accumulates, allowing
      scores to remain comparable across different routes and time periods.<br><br>

      The constant <code>15</code> controls the scaling of this saturation curve.
      Lower values make the index rise quickly; higher values make it increase more gradually.
    </div>
  </div>
</div>

<script>
  const RADIUS_KM = {radius_km};
  const HALF_LIFE_DAYS = {half_life_days};

  const $ = (id) => document.getElementById(id);

  function escapeHtml(s) {{
    return (s || '').replace(/[&<>"']/g, (c) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
  }}

  function formatLocal(ts) {{
    return ts || '—';
  }}

  function setLastUpdated(isoUtc) {{
    $('lastUpdated').textContent = formatLocal(isoUtc);
  }}

  function setStatusText(msg) {{
    $('statusText').textContent = msg || '—';
  }}

  async function loadIncidents() {{
    const res = await fetch('/api/incidents?ts=' + Date.now(), {{ cache: 'no-store' }});
    if (!res.ok) throw new Error('Failed to load incidents.json');
    return await res.json();
  }}

  async function loadSummary() {{
    const res = await fetch('/api/summary?ts=' + Date.now(), {{ cache: 'no-store' }});
    if (!res.ok) return null;
    return await res.json();
  }}

  async function triggerServerRefresh() {{
    const res = await fetch('/api/refresh', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{}}),
      cache: 'no-store'
    }});
    if (!res.ok) {{
      const txt = await res.text();
      throw new Error('Refresh failed: ' + txt);
    }}
    return await res.json();
  }}

  function toRiskIndex(raw) {{
    const scaled = 100 * (1 - Math.exp(-raw / 15));
    return Math.max(0, Math.min(100, scaled));
  }}

  function recencyWeight(ageDays) {{
    return Math.pow(0.5, (ageDays / HALF_LIFE_DAYS));
  }}

  function proximityWeight(distKm) {{
    return Math.exp(-distKm / RADIUS_KM);
  }}

  function haversineKm(lat1, lon1, lat2, lon2) {{
    const R = 6371.0;
    const toRad = Math.PI / 180.0;
    const dlat = (lat2 - lat1) * toRad;
    const dlon = (lon2 - lon1) * toRad;
    const a = Math.sin(dlat/2)**2
            + Math.cos(lat1*toRad) * Math.cos(lat2*toRad) * Math.sin(dlon/2)**2;
    return 2 * R * Math.asin(Math.sqrt(a));
  }}

  function pointToPolylineKm(lat, lon, poly) {{
    function dist2(a, b) {{ return (a[0]-b[0])**2 + (a[1]-b[1])**2; }}
    let best = Infinity;
    const p = [lat, lon];

    for (let i = 0; i < poly.length - 1; i++) {{
      const v = poly[i];
      const w = poly[i+1];
      const l2 = dist2(v, w);
      let t = 0.0;
      if (l2 > 0) {{
        t = ((p[0]-v[0])*(w[0]-v[0]) + (p[1]-v[1])*(w[1]-v[1])) / l2;
        t = Math.max(0.0, Math.min(1.0, t));
      }}
      const proj = [v[0] + t*(w[0]-v[0]), v[1] + t*(w[1]-v[1])];
      best = Math.min(best, haversineKm(p[0], p[1], proj[0], proj[1]));
    }}
    return best;
  }}

  function densify(points, stepsPerSeg=12) {{
    if (!points || points.length < 2) return points || [];
    const out = [];
    for (let i=0; i<points.length-1; i++) {{
      const a = points[i];
      const b = points[i+1];
      for (let s=0; s<stepsPerSeg; s++) {{
        const t = s / stepsPerSeg;
        out.push([a[0] + t*(b[0]-a[0]), a[1] + t*(b[1]-a[1])]);
      }}
    }}
    out.push(points[points.length-1]);
    return out;
  }}

  function hashColor(str) {{
    let h = 2166136261;
    for (let i=0; i<str.length; i++) {{
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }}
    const hue = Math.abs(h) % 360;
    return `hsl(${{hue}} 85% 55%)`;
  }}

  function colorForCategory(cat) {{
    const t = (cat || '').toLowerCase();
    if (t.includes('attack')) return '#ef4444';
    if (t.includes('suspicious')) return '#facc15';
    return hashColor(cat || 'unknown');
  }}

  const LANES = {{
    "Kuwait → Qatar": [
      [29.3759, 47.9774],
      [28.7000, 49.6000],
      [27.6000, 50.8000],
      [26.6000, 51.3000],
      [25.9300, 51.5600],
    ],
    "Kuwait → Dubai": [
      [29.3759, 47.9774],
      [28.4000, 49.8000],
      [27.2000, 51.8000],
      [26.0000, 53.8000],
      [25.0110, 55.0620],
    ],
    "Qatar → Arabian Sea": [
      [25.9300, 51.5600],
      [26.3000, 53.6000],
      [26.6000, 56.2500],
      [25.0000, 58.7000],
      [23.5000, 61.0000],
    ]
  }};

  let CURRENT_LANE_NAME = Object.keys(LANES)[0];
  let CURRENT_LANE = densify(LANES[CURRENT_LANE_NAME], 14);

  const map = L.map('map', {{ worldCopyJump: true }}).setView([25.0, 54.0], 5);

  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    maxZoom: 19,
    attribution: '&copy; OpenStreetMap &copy; CARTO'
  }}).addTo(map);

  const incidentLayer = L.layerGroup().addTo(map);
  let laneLine = L.polyline(CURRENT_LANE, {{ weight: 4, opacity: 0.95, smoothFactor: 2.0 }}).addTo(map);

  function bucketLabel(it) {{
    const c = (it && it.incidentTypeName) ? String(it.incidentTypeName).trim() : '';
    if (!c) return null;
    const low = c.toLowerCase();
    if (low === 'none' || low === 'other') return null;
    return c;
  }}

  function getAllBuckets(data) {{
    const set = new Set();
    for (const it of data) {{
      const b = bucketLabel(it);
      if (b) set.add(b);
    }}
    return Array.from(set).sort();
  }}

  function buildChecklist(buckets) {{
    const box = $('categoryChecks');
    box.innerHTML = '';

    const allRow = document.createElement('label');
    allRow.className = 'checkrow';
    allRow.innerHTML = `<input type="checkbox" id="chk_all" checked />
                        <span class="dot" style="background:rgba(255,255,255,0.25)"></span>
                        <span>All</span>`;
    box.appendChild(allRow);

    for (const b of buckets) {{
      const col = colorForCategory(b);
      const row = document.createElement('label');
      row.className = 'checkrow';
      row.innerHTML = `<input type="checkbox" class="catChk" data-cat="${{escapeHtml(b)}}" checked />
                       <span class="dot" style="background:${{col}}"></span>
                       <span>${{escapeHtml(b)}}</span>`;
      box.appendChild(row);
    }}

    const chkAll = $('chk_all');
    const catChks = () => Array.from(document.querySelectorAll('.catChk'));

    function setAll(checked) {{ for (const el of catChks()) el.checked = checked; }}

    function selectedSet() {{
      const set = new Set();
      for (const el of catChks()) if (el.checked) set.add(el.getAttribute('data-cat'));
      return set;
    }}

    function syncAllCheckbox() {{
      const els = catChks();
      const allChecked = els.length > 0 && els.every(e => e.checked);
      chkAll.checked = allChecked;
      chkAll.indeterminate = !allChecked && els.some(e => e.checked);
    }}

    chkAll.addEventListener('change', () => {{ setAll(chkAll.checked); syncAllCheckbox(); update(true); }});
    box.addEventListener('change', (e) => {{
      if (e.target && e.target.classList.contains('catChk')) {{ syncAllCheckbox(); update(true); }}
    }});

    syncAllCheckbox();
    return selectedSet;
  }}

  function buildLaneSelect() {{
    const sel = $('laneSelect');
    sel.innerHTML = '';
    for (const name of Object.keys(LANES)) {{
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      sel.appendChild(opt);
    }}
    sel.value = CURRENT_LANE_NAME;

    sel.addEventListener('change', () => {{
      CURRENT_LANE_NAME = sel.value;
      CURRENT_LANE = densify(LANES[CURRENT_LANE_NAME], 14);
      laneLine.setLatLngs(CURRENT_LANE);
      update(true);
    }});
  }}

  function render(allData, selectedBuckets, shouldFit) {{
    const filtered = allData.filter(it => {{
      const b = bucketLabel(it);
      return b && selectedBuckets.has(b);
    }});

    incidentLayer.clearLayers();
    const markers = [];

    $('nIncidents').textContent = filtered.length;

    let raw = 0.0;
    const listBox = $('incidentsList');
    listBox.innerHTML = '';

    for (const it of [...filtered].sort((a,b) => (a.age_days||0) - (b.age_days||0)).slice(0, 250)) {{
      const bucket = bucketLabel(it) || '';
      const col = colorForCategory(bucket);

      const distKm = pointToPolylineKm(it.lat, it.lon, CURRENT_LANE);
      const recW = recencyWeight(it.age_days || 0);
      const proxW = proximityWeight(distKm);
      const contrib = (it.severity || 0) * recW * proxW;
      raw += contrib;

      const radius = Math.max(5, Math.min(12, 5 + (it.severity || 0) / 3));

      const m = L.circleMarker([it.lat, it.lon], {{
        radius, color: col, weight: 1, opacity: 0.95, fillColor: col, fillOpacity: 0.75
      }}).bindPopup(`
        <b>${{escapeHtml(it.id || '')}}</b><br/>
        <span class="pill">${{escapeHtml(bucket)}}</span><br/><br/>
        ${{escapeHtml(it.incidentTypeName || '')}} • ${{escapeHtml(it.place || '')}}<br/>
        sev: ${{(it.severity || 0).toFixed(1)}}/20<br/>
        age: ${{(it.age_days || 0).toFixed(1)}} days<br/>
        dist to lane: ${{distKm.toFixed(0)}} km<br/><br/>
        <div style="color:#9aa4af; font-size:12px; white-space:pre-wrap;">${{escapeHtml((it.otherDetails || '').slice(0, 600))}}${{(it.otherDetails||'').length>600?'…':''}}</div>
      `);

      m.addTo(incidentLayer);
      markers.push(m);

      const div = document.createElement('div');
      div.className = 'incident';
      div.innerHTML = `
        <h4>${{escapeHtml(it.incidentTypeName || it.id || 'Incident')}} — ${{escapeHtml(it.place || '')}}</h4>
        <div class="meta">
          <span class="pill"><span class="dot" style="background:${{col}}; vertical-align:middle;"></span> ${{escapeHtml(bucket)}}</span>
          <span class="pill">sev ${{(it.severity || 0).toFixed(1)}}/20</span>
          <span class="pill">${{(it.age_days || 0).toFixed(1)}}d ago</span>
          <span class="pill">${{distKm.toFixed(0)}} km</span>
        </div>
        <div class="desc">${{escapeHtml((it.otherDetails || '').slice(0, 700))}}${{(it.otherDetails||'').length>700?'…':''}}</div>
      `;
      listBox.appendChild(div);
    }}

    $('riskFactor').textContent = toRiskIndex(raw).toFixed(1) + " / 100";

    if (shouldFit && markers.length) {{
      const group = L.featureGroup([...markers, laneLine]);
      map.fitBounds(group.getBounds().pad(0.2));
    }}
    return markers;
  }}

  let ALL = [];
  let getSelectedSet = null;

  function update(refit) {{
    const sel = getSelectedSet ? getSelectedSet() : new Set();
    render(ALL, sel, refit);
  }}

  // --------- Risk modal wiring ----------
  const riskModal = $('riskModal');
  function openRiskModal() {{
    riskModal.classList.add('open');
    riskModal.setAttribute('aria-hidden', 'false');
  }}
  function closeRiskModal() {{
    riskModal.classList.remove('open');
    riskModal.setAttribute('aria-hidden', 'true');
  }}
  $('riskInfoBtn').addEventListener('click', openRiskModal);
  $('riskModalClose').addEventListener('click', closeRiskModal);
  riskModal.addEventListener('click', (e) => {{ if (e.target === riskModal) closeRiskModal(); }});
  document.addEventListener('keydown', (e) => {{
    if (e.key === 'Escape' && riskModal.classList.contains('open')) closeRiskModal();
  }});

  async function boot() {{
    buildLaneSelect();

    ALL = await loadIncidents();
    const buckets = getAllBuckets(ALL);
    getSelectedSet = buildChecklist(buckets);
    update(true);

    const summary = await loadSummary();
    setLastUpdated(summary && summary.generated_utc ? summary.generated_utc : null);
    setStatusText(Array.isArray(ALL) ? `OK (${{ALL.length}} incidents)` : 'OK');

    $('refreshBtn').addEventListener('click', async () => {{
      const btn = $('refreshBtn');
      btn.disabled = true;
      setStatusText('Refreshing…');

      try {{
        const info = await triggerServerRefresh();

        ALL = await loadIncidents();
        const buckets2 = getAllBuckets(ALL);
        getSelectedSet = buildChecklist(buckets2);
        update(false);

        setLastUpdated(info && info.generated_utc ? info.generated_utc : null);
        setStatusText(typeof info.n === 'number' ? `OK (${{info.n}} incidents)` : 'OK');
      }} catch (err) {{
        const msg = (err && err.message) ? err.message : String(err);
        setStatusText('Failed');
        alert(msg);
      }} finally {{
        btn.disabled = false;
      }}
    }});
  }}

  boot().catch(err => alert(err.message));
</script>
</body>
</html>
"""


# ---------------------------
# Local server: /api/refresh reruns fetch/enrich/write
# ---------------------------
_build_lock = threading.Lock()


def run_pipeline(radius_km: float, half_life_days: float) -> Dict[str, Any]:
    incidents = fetch_incidents()
    enriched = enrich(incidents)
    write_artifacts(enriched, radius_km=radius_km, half_life_days=half_life_days)
    return {
        "ok": True,
        "generated_utc": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "n": len(enriched),
        "params": {"radius_km": radius_km, "half_life_days": half_life_days},
    }


class Handler(SimpleHTTPRequestHandler):
    # Serve files from DIST_DIR
    def translate_path(self, path: str) -> str:
        # Force everything to be relative to dist/
        # SimpleHTTPRequestHandler will join to current working dir; we override.
        parsed = urlparse(path).path
        rel = parsed.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel = rel + "index.html"
        return str((DIST_DIR / rel).resolve())

    def do_POST(self) -> None:
        if self.path != "/api/refresh":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        # Shared server config injected via server attributes
        radius_km = getattr(self.server, "radius_km", 200.0)
        half_life_days = getattr(self.server, "half_life_days", 14.0)

        # Ensure only one refresh runs at a time
        with _build_lock:
            try:
                info = run_pipeline(radius_km=radius_km, half_life_days=half_life_days)
                body = json.dumps(info).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                msg = (str(e) or "refresh error").encode("utf-8")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

    def log_message(self, format: str, *args: Any) -> None:
        # quieter logs
        return


def serve(dist_dir: Path, host: str, port: int, radius_km: float, half_life_days: float) -> None:
    dist_dir.mkdir(exist_ok=True)

    # Ensure at least one build exists before serving
    if not INCIDENTS_OUT.exists() or not HTML_OUT.exists() or not SUMMARY_OUT.exists():
        run_pipeline(radius_km=radius_km, half_life_days=half_life_days)

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    with ThreadingHTTPServer((host, port), Handler) as httpd:
        httpd.radius_km = radius_km
        httpd.half_life_days = half_life_days
        print(f"Serving dist/ at http://{host}:{port}/")
        print("Refresh endpoint: POST /api/refresh (called by the button)")
        httpd.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--radius-km", type=float, default=200.0, help="Proximity decay scale in km")
    ap.add_argument("--half-life-days", type=float, default=14.0, help="Recency half-life in days")
    ap.add_argument("--serve", action="store_true", help="Run local server so Refresh can rerun pipeline")
    ap.add_argument("--host", type=str, default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    # Always do a build (so dist artifacts exist)
    info = run_pipeline(radius_km=args.radius_km, half_life_days=args.half_life_days)

    print("Wrote:")
    print(" -", INCIDENTS_OUT.resolve())
    print(" -", HTML_OUT.resolve())
    print(" -", SUMMARY_OUT.resolve())
    print(f"Params: radius_km={args.radius_km} half_life_days={args.half_life_days}")
    print("Note: Risk Index is computed client-side based on selected lane.")
    print("Note: For the Refresh button to rerun the pipeline, you MUST run with --serve.")

    if args.serve:
        serve(DIST_DIR, host=args.host, port=args.port, radius_km=args.radius_km, half_life_days=args.half_life_days)


if __name__ == "__main__":
    main()