from fastapi import FastAPI, HTTPException, Query, Header, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from typing import Optional, List
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
import csv
import io
import json
import os

from database import db
from drain_analysis import drain_analyzer

# Fallback for rows stored before the detector recorded its own classification
SEVERITY_TO_CLASSIFICATION = {
    "INFO": "Benign",
    "LOW": "Benign",
    "MEDIUM": "Needs Attention",
    "HIGH": "Anomaly",
    "CRITICAL": "Anomaly",
}

CLASSIFICATIONS = ["Anomaly", "Needs Attention", "Benign", "Unanalyzed"]
TEMPLATE_CLASSIFICATIONS = ["Anomaly", "Needs Attention"]
EXPORT_MAX_ROWS = int(os.getenv("EXPORT_MAX_ROWS", "100000"))

def get_classification(incident):
    return incident.get("classification") or SEVERITY_TO_CLASSIFICATION.get(incident.get("severity"), "Unknown")

app = FastAPI(
    title = "Red Flags API",
    description = "REST API for querying security incidents detected.",
    version = "1.0.0",
    docs_url = "/docs",
    redoc_url = "/redoc"
)

origins = [
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:7274",
    "http://192.168.6.123:7274",
    "https://redflags.iee.ihu.gr",
    "https://api.redflags.iee.ihu.gr",
    "https://ventricular-ariah-burly.ngrok-free.dev",
]
# Extra dashboard origins, e.g. "http://10.0.0.20:7275,https://redflags.example.org"
origins += [o.strip().rstrip("/") for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,   
    allow_credentials=True,
    allow_methods=["*"],     
    allow_headers=["*"],
)

# Limit request rate
limiter = Limiter(key_func = get_remote_address)
app.state.Limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API key authentication
#API_KEY = os.getenv("API_KEY", None)

#def verify_api_key(x_api_key):
#    if API_KEY and x_api_key != API_KEY:
#        raise HTTPException(status_code = 401, detail = "Invalid or missing API key")
#    return True

@app.get("/")
@limiter.limit("100/minute")
async def root(request: Request):
    return {
        "service": "Red Flags API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "incidents": "/incidents",
            "statistics": "/statistics"
        }
    }

@app.get("/raw-logs/recent")
@limiter.limit("100/minute")
async def get_recent_raw_logs(
    request: Request,
    n: int = Query(100, ge=1, le=1000, description="Number of recent logs to return (max 1000)"),
    log_type: Optional[str] = Query(None, description="Filter by log type (system, windows, web, ids, firewall, fim, audit)"),
    source_host: Optional[str] = Query(None, description="Filter by source host (Wazuh agent name)")
):
    '''Most recent Wazuh alerts received from the indexer.'''
    try:
        logs = db.get_recent_alerts(
            n = n,
            log_type = log_type,
            source_host = source_host
        )

        return {
            "total_returned": len(logs),
            "logs": logs,
            "filters": {
                "n": n,
                "log_type": log_type,
                "source_host": source_host
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = f"Failed to read raw logs: {str(e)}"
        )
    
@app.get("/raw-logs/stats")
@limiter.limit("100/minute")
async def get_raw_log_stats(request: Request):
    try:
        return db.get_alert_sources()
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = f"Failed to get log statistics: {str(e)}"
        )


@app.get("/incidents")
@limiter.limit("100/minute")
async def list_incidents(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Number of results (max 100)"),
    offset: int = Query(0, ge=0, description = "Skip N results (pagination)"),
    severity: Optional[str] = Query(None, description = "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    log_type: Optional[str] = Query(None, description="Filter by log type (system, windows, web, ids, firewall, fim, audit)"),
    source_host: Optional[str] = Query(None, description="Filter by source host"),
    hours: Optional[int] = Query(None, description="Last N hours (e.g., 24)"),
    classification: Optional[str] = Query(None, description="Filter by classification (Anomaly, Needs Attention, Benign, Unanalyzed)")
    ):
    try:
        # Date range if hours is provided
        date_from = None
        if hours:
            date_from = datetime.now() - timedelta(hours=hours)

        incidents = db.get_incidents(
            limit = limit,
            offset = offset,
            severity = severity,
            log_type = log_type,
            source_host = source_host,
            date_from = date_from,
            classification = classification
        )

        return {
            "total_returned": len(incidents),
            "limit": limit,
            "offset": offset,
            "filters": {
                "severity": severity,
                "log_type": log_type,
                "source_host": source_host,
                "hours": hours,
                "classification": classification
            },
            "incidents": [
                {**dict(i), "classification": get_classification(i)}
                for i in incidents
            ]
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")

EXPORT_CSV_COLUMNS = [
    "id", "created_at", "event_timestamp", "wazuh_alert_id", "log_type", "source_host",
    "rule_id", "rule_description", "severity", "classification", "is_anomaly", "confidence",
    "event_category", "summary", "benign_explanation", "evidence", "mitre", "raw_log_message"
]

def _csv_safe(value):
    '''Neutralise spreadsheet formulas: log content is attacker-controlled.'''
    if value is None:
        return ""
    if isinstance(value, list):
        value = " | ".join(str(v) for v in value)
    value = str(value)
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value

def _csv_row(incident):
    analysis = incident.get("analysis_result") or {}
    row = {
        "id": incident["id"],
        "created_at": incident["created_at"].isoformat() if incident.get("created_at") else None,
        "event_timestamp": incident["event_timestamp"].isoformat() if incident.get("event_timestamp") else None,
        "wazuh_alert_id": incident.get("wazuh_alert_id"),
        "log_type": incident.get("log_type"),
        "source_host": incident.get("source_host"),
        "rule_id": analysis.get("rule_id"),
        "rule_description": analysis.get("rule_description"),
        "severity": incident.get("severity"),
        "classification": get_classification(incident),
        "is_anomaly": incident.get("is_anomaly") if incident.get("is_anomaly") is not None else analysis.get("is_anomaly"),
        "confidence": analysis.get("confidence"),
        "event_category": analysis.get("event_category") or analysis.get("event_type"),
        "summary": analysis.get("summary") or analysis.get("description"),
        "benign_explanation": analysis.get("benign_explanation"),
        "evidence": analysis.get("evidence"),
        "mitre": analysis.get("mitre"),
        "raw_log_message": incident.get("raw_log_message"),
    }
    return [_csv_safe(row[col]) for col in EXPORT_CSV_COLUMNS]

@app.get("/incidents/export")
@limiter.limit("10/minute")
async def export_incidents(
    request: Request,
    format: str = Query("csv", pattern = "^(csv|ndjson)$", description = "csv (flat columns) or ndjson (full records incl. raw alert)"),
    severity: Optional[str] = Query(None, description = "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    log_type: Optional[str] = Query(None, description = "Filter by log type"),
    source_host: Optional[str] = Query(None, description = "Filter by source host"),
    classification: Optional[str] = Query(None, description = "Filter by classification (Anomaly, Needs Attention, Benign, Unanalyzed)"),
    hours: Optional[int] = Query(None, ge = 1, description = "Last N hours")
):
    '''Download analyzed logs (oldest first, at most EXPORT_MAX_ROWS rows).'''
    date_from = datetime.now() - timedelta(hours = hours) if hours else None
    rows = db.iter_export(
        max_rows = EXPORT_MAX_ROWS,
        severity = severity,
        log_type = log_type,
        source_host = source_host,
        classification = classification,
        date_from = date_from
    )

    def generate_csv():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(EXPORT_CSV_COLUMNS)
        for incident in rows:
            writer.writerow(_csv_row(incident))
            if buffer.tell() > 64 * 1024:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
        yield buffer.getvalue()

    def generate_ndjson():
        for incident in rows:
            record = {**dict(incident), "classification": get_classification(incident)}
            yield json.dumps(record, default = str, ensure_ascii = False) + "\n"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if format == "csv":
        body, media_type = generate_csv(), "text/csv; charset=utf-8"
    else:
        body, media_type = generate_ndjson(), "application/x-ndjson"

    return StreamingResponse(
        body,
        media_type = media_type,
        headers = {"Content-Disposition": f'attachment; filename="redflags-analyzed-logs-{timestamp}.{format}"'}
    )

@app.get("/incidents/{incident_id}")
@limiter.limit("100/minute")
async def get_incident(
    request: Request,
    incident_id: int
):
    try:
        incident = db.get_single_incident(incident_id)

        if not incident:
            raise HTTPException(status_code = 404, detail = f"Incident {incident_id} not found")

        return incident

    except HTTPException:
        raise
    except Exception as e:  # ← Missing except block!
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
@app.get("/statistics")
@limiter.limit("100/minute")
async def get_statistics(
    request: Request,
    hours: int = Query(24, ge=0, le=8760, description = "Time range in hours (0 for all-time, max 8760 = 1 year)")
):
    try:
        stats = db.get_stats(
            hours=hours
        )
        return stats
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    

@app.get("/search/ip/{ip_address}")
@limiter.limit("100/minute")
async def search_by_ip(
    request: Request,
    ip_address: str
):
    try:
        incidents = db.search_by_ip(ip_address)

        return {
            "ip_address": ip_address,
            "total_found": len(incidents),
            "incidents": incidents
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    
@app.get("/recent")
@limiter.limit("100/minute")
async def get_recent_incidents(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description = "Number of hours to look back (max 168 = 1 week)")
):
    try:
        incidents = db.get_recent(hours = hours)

        return {
            "hours": hours,
            "total_found": len(incidents),
            "incidents": incidents
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    
@app.post("/analyze/templates")
@limiter.limit("100/minute")
async def extract_attack_patterns(
    request: Request,
    hours: int = Query(4, ge=1, le=8760, description = "Hours to analyze"),
    log_type: Optional[str] = Query(None, description="Filter by log type"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
    classification: Optional[str] = Query(None, description="Anomaly or Needs Attention (default: both)")
):
    """
    Extract templates for Anomaly and Needs Attention incidents using the Drain3 parser

    **Purpose**: Identify attack patterns over time
    **Use case**: Dashboard button "Analyze Attack Patterns"

    **Example requests**:
    - POST /analyze/templates?hours=4
    - POST /analyze/templates?hours=24&severity=HIGH
    - POST /analyze/templates?hours=4&classification=Anomaly
    """
    # The dashboard sends its filters as a JSON body; accept those as well as query parameters.
    try:
        body = await request.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        if "hours" not in request.query_params and body.get("hours"):
            try:
                hours = max(1, min(int(body["hours"]), 8760))
            except (TypeError, ValueError):
                raise HTTPException(status_code = 400, detail = "hours must be an integer")
        log_type = log_type or body.get("log_type")
        severity = severity or body.get("severity")
        classification = classification or body.get("classification")

    if classification and classification not in TEMPLATE_CLASSIFICATIONS:
        raise HTTPException(
            status_code = 400,
            detail = f"classification must be one of {TEMPLATE_CLASSIFICATIONS}"
        )
    classifications = [classification] if classification else TEMPLATE_CLASSIFICATIONS

    try:
        logs = db.get_incidents_by_timerange(
            hours = hours,
            log_type = log_type,
            severity = severity,
            classifications = classifications
        )
        filters = {
            "log_type": log_type,
            "severity": severity,
            "classifications": classifications
        }
        if not logs:
            return {
                "message": "No Anomaly or Needs Attention incidents found in specified time range",
                "total_logs_processed": 0,
                "total_templates": 0,
                "time_range_hours": hours,
                "filters": filters,
                "templates": []
            }
        results = drain_analyzer.extract_templates(logs)

        results["time_range_hours"] = hours
        results["filters"] = filters

        return results

    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = f"Template extraction failed: {str(e)}"
        )
    
@app.on_event("shutdown")
async def shutdown_event():
    db.close()

# Run with: uvicorn main:app --host 0.0.0.0 --port 8000








