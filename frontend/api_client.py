"""
ARGUS Frontend API Client
=========================
Encapsulates all REST API interactions between the ARGUS Streamlit Frontend
and the FastAPI backend service.
"""

import os
import logging
from typing import Dict, Any, Tuple, Optional
import requests

logger = logging.getLogger(__name__)

# Backend URL configuration from environment variables
API_BASE_URL = os.getenv("VITE_API_BASE_URL") or os.getenv("ARGUS_API_URL") or "http://localhost:8000"
DEFAULT_TENANT_ID = os.getenv("ARGUS_TENANT_ID", "default")


def get_headers(tenant_id: Optional[str] = None) -> Dict[str, str]:
    """Generates standard request headers including tenant isolation header."""
    return {
        "X-Tenant-ID": tenant_id or DEFAULT_TENANT_ID,
        "Accept": "application/json",
    }


def get_case_summary(case_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> Dict[str, Any]:
    """Fetches real case statistics and overview from GET /cases/{case_id}."""
    url = f"{API_BASE_URL.rstrip('/')}/cases/{case_id}"
    try:
        resp = requests.get(url, headers=get_headers(tenant_id), timeout=10)
        if resp.status_code == 200:
            return {"success": True, "data": resp.json()}
        elif resp.status_code == 404:
            return {"success": False, "error": f"Case '{case_id}' not found.", "status_code": 404}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}", "status_code": resp.status_code}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Unable to connect to ARGUS Backend at {API_BASE_URL}. Ensure backend service is running.", "status_code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "status_code": 500}


def get_report_json(case_id: str, allow_unreviewed: bool = True, tenant_id: str = DEFAULT_TENANT_ID) -> Dict[str, Any]:
    """Fetches full structured finding and report data from GET /reports/{case_id}/report?format=json."""
    url = f"{API_BASE_URL.rstrip('/')}/reports/{case_id}/report"
    params = {
        "format": "json",
        "allow_unreviewed": "true" if allow_unreviewed else "false"
    }
    try:
        resp = requests.get(url, params=params, headers=get_headers(tenant_id), timeout=15)
        if resp.status_code == 200:
            return {"success": True, "data": resp.json()}
        elif resp.status_code == 404:
            return {"success": False, "error": f"No report found for case '{case_id}'.", "status_code": 404}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}", "status_code": resp.status_code}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Unable to connect to ARGUS Backend at {API_BASE_URL}.", "status_code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "status_code": 500}


def get_report_html(case_id: str, allow_unreviewed: bool = True, tenant_id: str = DEFAULT_TENANT_ID) -> Dict[str, Any]:
    """Fetches rendered HTML report from GET /reports/{case_id}/report?format=html."""
    url = f"{API_BASE_URL.rstrip('/')}/reports/{case_id}/report"
    params = {
        "format": "html",
        "allow_unreviewed": "true" if allow_unreviewed else "false"
    }
    headers = get_headers(tenant_id)
    headers["Accept"] = "text/html"
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            return {"success": True, "html": resp.text}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}", "status_code": resp.status_code}
    except Exception as e:
        return {"success": False, "error": str(e), "status_code": 500}


def get_report_pdf(case_id: str, allow_unreviewed: bool = True, tenant_id: str = DEFAULT_TENANT_ID) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Fetches PDF report binary from GET /reports/{case_id}/report?format=pdf.
    Handles graceful fallback if native GTK+/Pango libraries are missing on Windows (HTTP 400/503).
    """
    url = f"{API_BASE_URL.rstrip('/')}/reports/{case_id}/report"
    params = {
        "format": "pdf",
        "allow_unreviewed": "true" if allow_unreviewed else "false"
    }
    headers = get_headers(tenant_id)
    headers["Accept"] = "application/pdf"
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=25)
        if resp.status_code == 200:
            return resp.content, None
        elif resp.status_code in (400, 503):
            # Graceful message when WeasyPrint native libraries are missing
            err_msg = "PDF export unavailable: Native PDF rendering library (GTK+/Pango) is missing on host platform. Please export as HTML or JSON instead."
            return None, err_msg
        else:
            return None, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return None, f"PDF export failed: {e}"


def upload_evidence(file_bytes: bytes, filename: str, case_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> Dict[str, Any]:
    """Uploads real evidence file to POST /evidence/upload."""
    url = f"{API_BASE_URL.rstrip('/')}/evidence/upload"
    headers = {
        "X-Tenant-ID": tenant_id or DEFAULT_TENANT_ID,
    }
    files = {
        "file": (filename, file_bytes, "application/octet-stream")
    }
    data = {
        "case_id": case_id
    }
    try:
        resp = requests.post(url, files=files, data=data, headers=headers, timeout=120)
        if resp.status_code == 200:
            return {"success": True, "data": resp.json()}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}", "status_code": resp.status_code}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Unable to connect to ARGUS Backend at {API_BASE_URL}.", "status_code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "status_code": 500}


def query_case(case_id: str, query: str, tenant_id: str = DEFAULT_TENANT_ID) -> Dict[str, Any]:
    """Sends analyst query to POST /cases/{case_id}/query."""
    url = f"{API_BASE_URL.rstrip('/')}/cases/{case_id}/query"
    payload = {
        "query": query
    }
    try:
        resp = requests.post(url, json=payload, headers=get_headers(tenant_id), timeout=30)
        if resp.status_code == 200:
            return {"success": True, "data": resp.json()}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}", "status_code": resp.status_code}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Unable to connect to ARGUS Backend at {API_BASE_URL}.", "status_code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "status_code": 500}
