from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.triage import settings
from src.triage.agents.orchestrator import TriagePipeline

BASE = Path(__file__).resolve().parent

app = FastAPI(title="Triage Console")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

_pipeline: TriagePipeline = None

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    return resp


def pipeline() -> TriagePipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = TriagePipeline()
    return _pipeline


def _ensure_data(store) -> None:
    if not store.list_cases():
        pipeline().generate()


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _flash(request: Request) -> tuple[str, str]:
    f = request.query_params.get("flash", "")
    return (f, f)


def _computed_stats(store) -> dict:
    cases = store.list_cases()
    verdicts = {c["id"]: store.get_verdict(c["id"]) for c in cases}

    statuses = store.stats()["cases"]
    severity = {s: 0 for s in SEVERITY_ORDER}
    for c in cases:
        sev = c.get("implied_severity", "low") or "low"
        severity[sev] = severity.get(sev, 0) + 1

    gone = verdicts.values()
    confidence = [v.confidence for v in gone if v is not None]
    avg_conf = sum(confidence) / len(confidence) if confidence else 0.0

    disposition_counts: dict[str, int] = {}
    for v in gone:
        if v is None:
            continue
        key = v.disposition.value
        disposition_counts[key] = disposition_counts.get(key, 0) + 1
    total_disp = sum(disposition_counts.values()) or 1
    dispositions = sorted(
        ((d, {"count": n, "pct": round(n / total_disp * 100, 1)})
         for d, n in disposition_counts.items()),
        key=lambda x: -x[1]["count"],
    )

    alerts = store.stats()
    total_alerts = alerts["total_alerts"] or 0
    suppressed = alerts["suppressed_alerts"] or 0

    return {
        "open": statuses.get("open", 0) + statuses.get("triaging", 0),
        "investigated": statuses.get("resolved", 0),
        "auto_resolved": statuses.get("auto_resolved", 0),
        "total_alerts": total_alerts,
        "events": alerts["events"] or 0,
        "suppressed_alerts": suppressed,
        "suppression_rate": (suppressed / total_alerts) if total_alerts else 0.0,
        "avg_confidence": avg_conf,
        "severity": severity,
        "dispositions": dispositions,
    }


def _queue_view(store, status=None, severity=None, disposition=None, q=None):
    rows = store.list_cases()
    verdicts = {r["id"]: store.get_verdict(r["id"]) for r in rows}
    q = (q or "").strip().lower()

    out = []
    for row in rows:
        ver = verdicts.get(row["id"])
        if status and row["status"] != status:
            continue
        if severity and row.get("implied_severity") != severity:
            continue
        if disposition and (not ver or ver.disposition.value != disposition):
            continue
        if q and q not in row["title"].lower() and q not in row["id"].lower():
            continue
        case = store.get_case(row["id"])
        row = {**row, "entities": case.entities if case else None}
        out.append((row, ver))
    return out


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    store = pipeline().store
    _ensure_data(store)
    stats = _computed_stats(store)
    recent = [(c, store.get_verdict(c["id"])) for c in store.list_cases()[:8]]
    return templates.TemplateResponse(request, "overview.html", {
        "active": "overview",
        "stats": stats,
        "recent": recent,
        "llm_enabled": bool(settings.ANTHROPIC_API_KEY),
        "model": settings.TRIAGE_MODEL,
    })


@app.get("/queue", response_class=HTMLResponse)
def queue(request: Request, status: str = "", severity: str = "", disposition: str = "", q: str = ""):
    store = pipeline().store
    _ensure_data(store)
    cases = _queue_view(store, status=status, severity=severity, disposition=disposition, q=q)
    return templates.TemplateResponse(request, "queue.html", {
        "active": "queue",
        "cases": cases,
        "filters": {"status": status, "severity": severity, "disposition": disposition, "q": q},
        "llm_enabled": bool(settings.ANTHROPIC_API_KEY),
        "model": settings.TRIAGE_MODEL,
    })


@app.get("/case/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str):
    store = pipeline().store
    _ensure_data(store)
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    verdict = store.get_verdict(case_id)
    alerts = store.get_alerts()
    events = store.get_events()
    from src.triage.intel.reputation import ThreatIntel
    intel = ThreatIntel()
    intel_row = {ip: intel.lookup(ip) for ip in case.entities.ips if ip}
    return templates.TemplateResponse(request, "case.html", {
        "active": "queue",
        "case": case,
        "verdict": verdict,
        "alerts": [alerts[a] for a in case.alerts if a in alerts],
        "events": [events[e] for e in case.event_ids if e in events],
        "intel": intel_row,
        "llm_enabled": bool(settings.ANTHROPIC_API_KEY),
        "model": settings.TRIAGE_MODEL,
    })


@app.post("/generate")
def regen(request: Request):
    stats = pipeline().generate()
    if _wants_html(request):
        return _redirect("/?flash=generated")
    return JSONResponse({"ok": True, "stats": stats})


@app.post("/triage/{case_id}")
def triage_case_route(request: Request, case_id: str, dry_run: bool = False):
    try:
        v = pipeline().triage_case(case_id, llm=not dry_run)
    except KeyError:
        raise HTTPException(status_code=404, detail="case not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    payload = {
        "case_id": v.case_id,
        "disposition": v.disposition.value,
        "severity": v.severity.value,
        "confidence": v.confidence,
        "model": v.model,
        "llm_used": v.llm_used,
        "summary": v.summary,
    }
    if _wants_html(request):
        return _redirect(f"/case/{v.case_id}?flash=triaged")
    return JSONResponse(payload)


@app.post("/triage-all")
def triage_all_route(request: Request, dry_run: bool = False):
    results = pipeline().triage_all(llm=not dry_run)
    if _wants_html(request):
        return _redirect("/queue?flash=triaged-all")
    return JSONResponse({"ok": True, "results": results})


@app.get("/api/cases")
def api_cases():
    store = pipeline().store
    _ensure_data(store)
    out = []
    for c in store.list_cases():
        verdict = store.get_verdict(c["id"])
        out.append({**c,
                    "disposition": verdict.disposition.value if verdict else None,
                    "confidence": verdict.confidence if verdict else None})
    return JSONResponse(out)


@app.get("/api/case/{case_id}")
def api_case(case_id: str):
    store = pipeline().store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404)
    verdict = store.get_verdict(case_id)
    return JSONResponse({
        "case": case.model_dump(mode="json"),
        "verdict": verdict.model_dump(mode="json") if verdict else None,
    })


@app.get("/api/stats")
def api_stats():
    store = pipeline().store
    _ensure_data(store)
    return JSONResponse(_computed_stats(store))