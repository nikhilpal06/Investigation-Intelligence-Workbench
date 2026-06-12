"""
Investigation Intelligence Platform — Backend
Runs on port 8100.
- /extract  : PDF/TXT text extraction with page-level source traceability
- /analyze  : Proxies Claude API calls (avoids browser CORS issues)
- /health   : Health check

SETUP: Set your Anthropic API key on the line below.
"""

import os

# ── SET YOUR API KEY HERE ─────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "YOUR_API_KEY_HERE")
# ─────────────────────────────────────────────────────────────────────────────

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import pdfplumber
import io, re, traceback, json
import urllib.request

app = FastAPI(title="IIP Backend", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

SECTION_PATTERNS = [
    (r"deviation detail", "Deviation Details"),
    (r"classification detail", "Classification Details"),
    (r"causal analysis", "Causal Analysis"),
    (r"remediation summary", "Remediation Summary"),
    (r"impact summary", "Impact Summary"),
    (r"due date detail", "Due Date Details"),
    (r"investigation decision", "Investigation Decision"),
    (r"action item", "Action Items"),
    (r"complaint information", "Complaint Information"),
    (r"investigation \(yes\)", "Investigation"),
    (r"root cause", "Root Cause Analysis"),
    (r"risk review", "Risk Review"),
    (r"batch record", "Batch Record Review"),
    (r"closure", "Closure"),
    (r"signature", "Signatures"),
    (r"assessment", "Assessment"),
    (r"description", "Description"),
    (r"summary", "Summary"),
    (r"cause$", "Cause"),
]

def detect_section(text: str, page_num: int) -> str:
    t = text.lower()[:400]
    for pat, label in SECTION_PATTERNS:
        if re.search(pat, t):
            return label
    return f"Page {page_num}"

def clean_text(text: str) -> str:
    if not text: return ""
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]', ' ', text)
    return text.strip()

def safe_json(obj):
    raw = json.dumps(obj, ensure_ascii=False)
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', raw)
    return raw


@app.get("/health")
async def health():
    key_set = ANTHROPIC_API_KEY != "YOUR_API_KEY_HERE" and len(ANTHROPIC_API_KEY) > 20
    return {"status": "ok", "service": "IIP Backend v2.0", "api_key_configured": key_set}


@app.post("/analyze")
async def analyze(request: Request):
    """
    Proxy endpoint for Claude API calls.
    Receives the same body you would send to Anthropic directly,
    adds the API key server-side, returns the response.
    """
    if ANTHROPIC_API_KEY == "YOUR_API_KEY_HERE":
        resp = {"error": {"message": "API key not set in backend.py — open backend.py and set ANTHROPIC_API_KEY"}}
        return Response(content=safe_json(resp), media_type="application/json", status_code=400)

    try:
        body = await request.body()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = resp.read().decode("utf-8")
        return Response(content=result, media_type="application/json")

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        return Response(content=error_body, media_type="application/json", status_code=e.code)
    except Exception as e:
        resp = {"error": {"message": str(e)}}
        return Response(content=safe_json(resp), media_type="application/json", status_code=500)


@app.post("/extract")
async def extract_pdf(file: UploadFile = File(...)):
    fname = (file.filename or "unknown").lower()
    content = await file.read()

    if len(content) == 0:
        resp = {"success": False, "filename": file.filename, "error": "File is empty.",
                "full_text": "", "preview": "", "pages": [], "total_pages": 0}
        return Response(content=safe_json(resp), media_type="application/json")

    # Plain text
    if fname.endswith('.txt') or fname.endswith('.csv'):
        try:
            text = clean_text(content.decode('utf-8', errors='replace'))[:20000]
            resp = {"success": True, "filename": file.filename, "total_pages": 1,
                    "pages": [{"page_num": 1, "section": "Document", "text": text, "char_count": len(text)}],
                    "full_text": text, "preview": text[:1500], "error": None}
        except Exception as e:
            resp = {"success": False, "filename": file.filename, "error": str(e),
                    "full_text": "", "preview": "", "pages": [], "total_pages": 0}
        return Response(content=safe_json(resp), media_type="application/json")

    if not fname.endswith('.pdf'):
        resp = {"success": False, "filename": file.filename,
                "error": "Unsupported file type. Upload PDF or TXT.",
                "full_text": "", "preview": "", "pages": [], "total_pages": 0}
        return Response(content=safe_json(resp), media_type="application/json")

    # PDF extraction
    try:
        pages_data = []
        full_parts = []

        with pdfplumber.open(io.BytesIO(content)) as pdf:
            total_pages = len(pdf.pages)

            for i, page in enumerate(pdf.pages):
                page_num = i + 1
                try:
                    raw = page.extract_text(x_tolerance=3, y_tolerance=3) or ""
                    table_rows = []
                    for tbl in (page.extract_tables() or []):
                        for row in tbl:
                            cells = [str(c or "").strip() for c in (row or [])]
                            non_empty = [c for c in cells if c]
                            if non_empty:
                                table_rows.append(" | ".join(non_empty))
                    combined = clean_text(raw + ("\n" + "\n".join(table_rows) if table_rows else ""))
                    section = detect_section(combined, page_num)
                    pages_data.append({"page_num": page_num, "section": section,
                                       "text": combined[:3000], "char_count": len(combined)})
                    if combined:
                        full_parts.append(f"[Page {page_num} — {section} — {file.filename}]\n{combined}")
                except Exception as pe:
                    pages_data.append({"page_num": page_num, "section": f"Page {page_num}",
                                       "text": f"[Extraction error: {pe}]", "char_count": 0})

        total_chars = sum(p["char_count"] for p in pages_data)
        full_text = "\n\n".join(full_parts)
        if len(full_text) > 45000:
            full_text = full_text[:45000] + "\n\n[... truncated at 45,000 characters ...]"

        if total_chars < 50:
            resp = {"success": False, "filename": file.filename, "total_pages": total_pages,
                    "is_scanned": True, "pages": pages_data, "full_text": "", "preview": "",
                    "error": "PDF could not be read — no text layer detected. This PDF appears to be a scanned image. Please paste the case text manually in the text area below."}
        else:
            resp = {"success": True, "filename": file.filename, "total_pages": total_pages,
                    "pages": pages_data, "full_text": full_text, "preview": full_text[:1500], "error": None}

    except Exception as e:
        resp = {"success": False, "filename": file.filename, "total_pages": 0,
                "error": f"PDF extraction failed: {e}", "full_text": "", "preview": "",
                "pages": [], "debug": traceback.format_exc()[:300]}

    return Response(content=safe_json(resp), media_type="application/json")


if __name__ == "__main__":
    import uvicorn
    print("=" * 55)
    print("  Investigation Intelligence Platform — Backend")
    print("=" * 55)
    key_ok = ANTHROPIC_API_KEY != "YOUR_API_KEY_HERE" and len(ANTHROPIC_API_KEY) > 20
    if key_ok:
        print(f"  ✓ API key configured ({ANTHROPIC_API_KEY[:12]}...)")
    else:
        print("  ✗ API key NOT set — open backend.py and set ANTHROPIC_API_KEY")
    print(f"  ✓ Server starting on http://localhost:8100")
    print("=" * 55)
    uvicorn.run(app, host="0.0.0.0", port=8100, log_level="error")
