import json
import os
import threading
import time
import traceback
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, make_response, redirect, render_template, render_template_string, request, url_for
from werkzeug.utils import secure_filename
from xhtml2pdf import pisa

from analysis_engine import analyze_file

app = Flask(__name__)

UPLOAD_FOLDER = Path("uploads")
ANALYSIS_FOLDER = UPLOAD_FOLDER / "analysis"
STATUS_FOLDER = ANALYSIS_FOLDER / "status"
UPLOAD_FOLDER.mkdir(exist_ok=True)
ANALYSIS_FOLDER.mkdir(exist_ok=True)
STATUS_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["ANALYSIS_FOLDER"] = str(ANALYSIS_FOLDER)
app.config["STATUS_FOLDER"] = str(STATUS_FOLDER)

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Analysis Report</title>
    <style>
        @page { size: A4; margin: 14mm; }
        body { font-family: Arial, sans-serif; color: #0f172a; font-size: 11px; line-height: 1.45; }
        h1 { font-size: 24px; margin: 0 0 8px 0; }
        h2 { font-size: 15px; margin: 18px 0 8px 0; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }
        .summary { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px; border-radius: 6px; }
        table { width: 100%; border-collapse: collapse; margin: 8px 0 12px 0; table-layout: fixed; }
        th, td { border: 1px solid #cbd5e1; padding: 6px; vertical-align: top; word-break: break-word; }
        th { background: #e2e8f0; text-align: left; }
        .mono { font-family: Consolas, Monaco, monospace; font-size: 10px; }
        .no-evidence { color: #991b1b; font-style: italic; }
        .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 14px; }
        .download-btn, .back-link { display: inline-block; text-decoration: none; font-size: 11px; font-weight: bold; }
        .download-btn { background: #0f172a; color: #fff; padding: 9px 14px; border-radius: 6px; }
        .download-btn:hover { background: #1e293b; }
        .back-link { color: #0f172a; }
        .section-note { color: #475569; font-size: 10px; margin: 4px 0 10px 0; }
        .tag { display: inline-block; padding: 3px 8px; border-radius: 999px; background: #e2e8f0; margin: 2px 4px 2px 0; font-size: 10px; }
    </style>
</head>
<body>
    <div class="topbar">
        <a class="back-link" href="{{ dashboard_url }}">← Back to Dashboard</a>
        <a class="download-btn" href="{{ download_url }}">Download PDF</a>
    </div>

    <h1>Executive Summary</h1>
    <div class="summary">
        <div><strong>File:</strong> {{ analysis.filename }}</div>
        <div><strong>Type:</strong> {{ analysis.file_type.detected }}</div>
        <div><strong>Severity:</strong> {{ analysis.severity }}</div>
        <div><strong>Risk Score:</strong> {{ analysis.risk_score }}</div>
        <div><strong>Malware Present:</strong> {{ 'Yes' if analysis.malware_present else 'No evidence found.' }}</div>
        <div><strong>Family:</strong> {{ analysis.malware_family or 'No evidence found.' }}</div>
        <div><strong>Infection Status:</strong> {{ analysis.infection_status }}</div>
        <div><strong>Persistence Status:</strong> {{ analysis.persistence_status }}</div>
        <div><strong>Threat Active:</strong> {{ 'Yes' if analysis.threat_active else 'No evidence found.' }}</div>
        <p>{{ summary_text }}</p>
    </div>

    <h2>File Information</h2>
    <div class="section-note">Evidence extracted from the uploaded artifact only.</div>
    <table>
        <tr><th style="width: 24%">Property</th><th>Value</th></tr>
        <tr><td>Filename</td><td>{{ analysis.filename }}</td></tr>
        <tr><td>Detected Type</td><td>{{ analysis.file_type.detected }}</td></tr>
        <tr><td>Magic Signature</td><td>{{ analysis.file_type.magic }}</td></tr>
        <tr><td>Extension</td><td>{{ analysis.file_type.extension }}</td></tr>
        <tr><td>MIME Type</td><td>{{ analysis.file_type.mime_type }}</td></tr>
        <tr><td>Size</td><td class="mono">{{ analysis.metadata.size }} bytes</td></tr>
        <tr><td>Created</td><td class="mono">{{ analysis.metadata.created }}</td></tr>
        <tr><td>Modified</td><td class="mono">{{ analysis.metadata.modified }}</td></tr>
        <tr><td>Accessed</td><td class="mono">{{ analysis.metadata.accessed }}</td></tr>
    </table>

    <h2>Hash Analysis</h2>
    <div class="section-note">MD5, SHA1, and SHA256 values calculated from the uploaded file.</div>
    <table>
        <tr><th style="width: 18%">Algorithm</th><th>Hash</th></tr>
        <tr><td>MD5</td><td class="mono">{{ analysis.hashes.md5 }}</td></tr>
        <tr><td>SHA1</td><td class="mono">{{ analysis.hashes.sha1 }}</td></tr>
        <tr><td>SHA256</td><td class="mono">{{ analysis.hashes.sha256 }}</td></tr>
    </table>

    <h2>Malware Analysis</h2>
    <div class="section-note">Static detection, YARA, suspicious strings, and entropy.</div>
    <table>
        <tr><th style="width: 24%">Signal</th><th>Evidence</th></tr>
        <tr><td>Printable strings extracted</td><td class="mono">{{ analysis.strings.count }}</td></tr>
        <tr><td>Entropy</td><td class="mono">{{ analysis.entropy }}</td></tr>
        <tr><td>Malware family</td><td>{{ analysis.malware_family or 'No evidence found.' }}</td></tr>
        <tr><td>Overall verdict</td><td>{{ 'Malicious' if analysis.malware_present else 'Suspicious' if analysis.threat_active else 'Clean' if analysis.has_evidence else 'No evidence found.' }}</td></tr>
    </table>
    {% if analysis.yara_matches %}
    <table>
        <tr><th style="width: 22%">YARA Rule</th><th style="width: 18%">Namespace</th><th>Evidence</th></tr>
        {% for match in analysis.yara_matches %}
        <tr>
            <td>{{ match.rule }}</td>
            <td>{{ match.namespace or 'n/a' }}</td>
            <td>
                {% if match.tags %}<div>{% for tag in match.tags %}<span class="tag">{{ tag }}</span>{% endfor %}</div>{% endif %}
                <div class="mono">{{ match.meta }}</div>
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>IOC Analysis</h2>
    <div class="section-note">Domains, IPs, URLs, registry paths, hashes, and other indicators.</div>
    {% if analysis.iocs %}
    <table>
        <tr><th style="width: 18%">Type</th><th style="width: 42%">Value</th><th>Evidence</th></tr>
        {% for ioc in analysis.iocs %}
        <tr>
            <td>{{ ioc.type }}</td>
            <td class="mono">{{ ioc.value }}</td>
            <td>{{ ioc.description }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>Process Analysis</h2>
    <div class="section-note">Volatility3 output, if a memory dump was uploaded.</div>
    {% if analysis.memory_analysis.processes %}
    <table>
        <tr><th style="width: 10%">PID</th><th style="width: 18%">Name</th><th style="width: 10%">PPID</th><th style="width: 18%">Status</th><th>Evidence</th></tr>
        {% for proc in analysis.memory_analysis.processes %}
        <tr>
            <td class="mono">{{ proc.pid }}</td>
            <td>{{ proc.name }}</td>
            <td class="mono">{{ proc.ppid }}</td>
            <td>{{ proc.status }}</td>
            <td>{% if proc.evidence %}{% for item in proc.evidence %}<div>{{ item }}</div>{% endfor %}{% else %}No evidence found.{% endif %}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>Network Analysis</h2>
    <div class="section-note">Active connections and remote endpoints from Volatility3, if available.</div>
    {% if analysis.memory_analysis.network_connections %}
    <table>
        <tr><th style="width: 10%">PID</th><th style="width: 22%">Local</th><th style="width: 22%">Remote</th><th style="width: 12%">State</th><th>Evidence</th></tr>
        {% for row in analysis.memory_analysis.network_connections %}
        <tr>
            <td class="mono">{{ row.pid or 'Unknown' }}</td>
            <td class="mono">{{ row.local }}</td>
            <td class="mono">{{ row.remote }}</td>
            <td>{{ row.state }}</td>
            <td>{{ row.description }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>Timeline Reconstruction</h2>
    <div class="section-note">Only timestamped evidence from the uploaded file is shown here.</div>
    {% if analysis.timeline %}
    <table>
        <tr><th style="width: 24%">Timestamp</th><th style="width: 18%">Event</th><th style="width: 32%">Description</th><th>Evidence</th></tr>
        {% for event in analysis.timeline %}
        <tr>
            <td class="mono">{{ event.timestamp }}</td>
            <td>{{ event.event_type }}</td>
            <td>{{ event.description }}</td>
            <td>{{ event.evidence }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>Threat Assessment</h2>
    <div class="section-note">Malware state, persistence, and activity status are derived from collected evidence only.</div>
    <table>
        <tr><th style="width: 22%">Assessment</th><th>Value</th></tr>
        <tr><td>Malware Present</td><td>{{ 'Yes' if analysis.malware_present else 'No evidence found.' }}</td></tr>
        <tr><td>Threat Active</td><td>{{ 'Yes' if analysis.threat_active else 'No evidence found.' }}</td></tr>
        <tr><td>Severity</td><td>{{ analysis.severity }}</td></tr>
        <tr><td>Risk Score</td><td class="mono">{{ analysis.risk_score }}</td></tr>
        <tr><td>Persistence Status</td><td>{{ analysis.persistence_status }}</td></tr>
        <tr><td>Execution Status</td><td>{{ analysis.infection_status }}</td></tr>
    </table>

    <h2>Recommended Actions</h2>
    <div class="section-note">Actions are produced only from observed evidence and analysis results.</div>
    {% if analysis.recommended_actions %}
    <table>
        <tr><th style="width: 34%">Action</th><th>Evidence</th></tr>
        {% for item in analysis.recommended_actions %}
        <tr><td>{{ item.action }}</td><td>{{ item.evidence }}</td></tr>
        {% endfor %}
    </table>
    {% else %}<div class="no-evidence">No evidence found.</div>{% endif %}

    <h2>Evidence Collected</h2>
    <div class="section-note">Supporting evidence used across the report.</div>
    <table>
        <tr><th style="width: 24%">Section</th><th style="width: 28%">Value</th><th>Evidence</th></tr>
        {% for item in analysis.evidence_collected %}
        <tr>
            <td>{{ item.section }}</td>
            <td class="mono">{{ item.value }}</td>
            <td>{{ item.evidence }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


def save_analysis(analysis: dict) -> None:
    analysis_path = ANALYSIS_FOLDER / f"{analysis['analysis_id']}.json"
    analysis_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")


def load_analysis(analysis_id: str | None = None) -> dict | None:
    if not analysis_id:
        return None

    analysis_path = ANALYSIS_FOLDER / f"{analysis_id}.json"
    if not analysis_path.exists():
        return None
    return json.loads(analysis_path.read_text(encoding="utf-8"))


def dashboard_context(analysis: dict | None) -> dict:
    if not analysis:
        return {"processes": [], "iocs": [], "timeline": [], "clean_count": 0, "suspicious_count": 0, "malicious_count": 0, "analysis": None, "analysis_id": None, "evidence_profile": {"benign": 0, "suspicious": 0, "malicious": 0, "total": 0}}

    processes = analysis.get("memory_analysis", {}).get("processes", [])
    iocs = analysis.get("iocs", [])
    timeline = analysis.get("timeline", [])
    profile = analysis.get("evidence_profile") or {"benign": sum(1 for proc in processes if proc.get("status") == "Clean"), "suspicious": sum(1 for proc in processes if proc.get("status") == "Suspicious"), "malicious": 1 if analysis.get("malware_present") else 0, "total": 0}
    if not profile.get("total"):
        profile["total"] = profile.get("benign", 0) + profile.get("suspicious", 0) + profile.get("malicious", 0)

    return {"processes": processes, "iocs": iocs, "timeline": timeline, "clean_count": profile.get("benign", 0), "suspicious_count": profile.get("suspicious", 0), "malicious_count": profile.get("malicious", 0), "analysis": analysis, "analysis_id": analysis.get("analysis_id"), "evidence_profile": profile}


def render_report_html(analysis: dict) -> str:
    summary_text = build_summary_text(analysis)
    return render_template_string(
        REPORT_TEMPLATE,
        analysis=analysis,
        summary_text=summary_text,
        download_url=url_for('export_report', analysis_id=analysis['analysis_id']),
        dashboard_url=url_for('dashboard', analysis_id=analysis['analysis_id']),
    )


def build_summary_text(analysis: dict) -> str:
    if not analysis.get("has_evidence"):
        return "No evidence found."

    parts = []
    parts.append("Malware evidence was observed." if analysis.get("malware_present") else "No malware evidence was confirmed.")
    if analysis.get("threat_active"):
        parts.append("Active process or network evidence is present.")
    if analysis.get("memory_analysis", {}).get("code_injection"):
        parts.append("Code injection indicators were observed in memory analysis.")
    if analysis.get("memory_analysis", {}).get("persistence"):
        parts.append("Persistence indicators were observed.")
    if analysis.get("iocs"):
        parts.append(f"{len(analysis['iocs'])} IOC(s) were extracted from the artifact.")
    return " ".join(parts)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def status_file_path(job_id: str) -> Path:
    return STATUS_FOLDER / f"{job_id}.json"


def load_job_status(job_id: str) -> dict | None:
    path = status_file_path(job_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_job_status(job_id: str, status: dict) -> None:
    path = status_file_path(job_id)
    path.write_text(json.dumps(status, indent=2), encoding="utf-8")


def estimate_remaining_seconds(started_at: float, percent: int) -> int | None:
    if percent <= 0:
        return None
    elapsed = max(time.time() - started_at, 0.0)
    remaining = elapsed * (100 - percent) / max(percent, 1)
    return max(0, int(round(remaining)))


def initialize_job_status(job_id: str, filename: str, stored_path: str) -> dict:
    status = {
        "job_id": job_id,
        "analysis_id": None,
        "state": "queued",
        "stage": "Queued",
        "percent": 0,
        "eta_seconds": None,
        "logs": [f"File uploaded: {filename}"],
        "error": None,
        "filename": filename,
        "original_filename": filename,
        "stored_path": stored_path,
        "started_at": now_iso(),
        "updated_at": now_iso(),
        "completed_at": None,
    }
    save_job_status(job_id, status)
    return status


def start_analysis_job(job_id: str, stored_path: str, filename: str) -> None:
    thread = threading.Thread(target=run_analysis_job, args=(job_id, stored_path, filename), daemon=True)
    thread.start()


def run_analysis_job(job_id: str, stored_path: str, filename: str) -> None:
    started_at = time.time()

    def progress_callback(event: dict) -> None:
        current = load_job_status(job_id) or initialize_job_status(job_id, filename, stored_path)
        logs = list(current.get("logs", []))
        log_entry = event.get("log")
        if log_entry:
            logs.append(f"[{now_iso()}] {log_entry}")

        percent = int(event.get("percent", current.get("percent", 0)) or 0)
        current.update({
            "state": event.get("status", current.get("state", "running")),
            "stage": event.get("stage", current.get("stage", "Running")),
            "percent": max(0, min(100, percent)),
            "eta_seconds": estimate_remaining_seconds(started_at, percent),
            "logs": logs,
            "updated_at": now_iso(),
            "error": None,
        })
        save_job_status(job_id, current)

    try:
        progress_callback({"stage": "Detecting File Type...", "percent": 5, "log": "Starting analysis pipeline.", "status": "running"})
        analysis = analyze_file(stored_path, volatility_root=os.getenv("VOLATILITY3_PATH"), progress_callback=progress_callback, original_filename=filename)
        analysis["original_filename"] = filename
        analysis["filename"] = filename
        analysis["stored_path"] = stored_path
        save_analysis(analysis)

        finished = load_job_status(job_id) or initialize_job_status(job_id, filename, stored_path)
        finished.update({
            "analysis_id": analysis["analysis_id"],
            "state": "complete",
            "stage": "Finalizing Results...",
            "percent": 100,
            "eta_seconds": 0,
            "updated_at": now_iso(),
            "completed_at": now_iso(),
            "error": None,
        })
        finished.setdefault("logs", []).append(f"[{now_iso()}] Analysis saved and ready for dashboard access.")
        save_job_status(job_id, finished)
    except Exception as exc:
        failed = load_job_status(job_id) or initialize_job_status(job_id, filename, stored_path)
        failed.update({
            "state": "failed",
            "stage": "Analysis failed",
            "percent": 100,
            "eta_seconds": 0,
            "error": f"{exc}",
            "updated_at": now_iso(),
            "completed_at": now_iso(),
        })
        failed.setdefault("logs", []).append(f"[{now_iso()}] Failure: {exc}")
        failed.setdefault("logs", []).append(traceback.format_exc())
        save_job_status(job_id, failed)

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/upload_dump', methods=['POST'])
def upload_dump():
    uploaded_file = request.files.get('file')
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({'error': 'No file was uploaded.'}), 400

    filename = secure_filename(uploaded_file.filename) or 'uploaded_artifact.bin'
    saved_path = UPLOAD_FOLDER / f"{os.urandom(8).hex()}_{filename}"
    uploaded_file.save(saved_path)

    job_id = uuid4().hex
    initialize_job_status(job_id, filename, str(saved_path))
    start_analysis_job(job_id, str(saved_path), filename)

    return redirect(url_for('analyzing', job_id=job_id))

@app.route('/dashboard')
@app.route('/dashboard/<analysis_id>')
def dashboard(analysis_id: str | None = None):
    analysis = load_analysis(analysis_id)
    if analysis_id and not analysis:
        return 'No completed analysis is available yet. Please wait for the analyzing page to finish.', 404
    context = dashboard_context(analysis)
    return render_template('dashboard.html', **context)


@app.route('/analyzing/<job_id>')
def analyzing(job_id: str):
    status = load_job_status(job_id)
    if not status:
        return 'No analysis job is available. Upload a file first.', 404
    return render_template('analyzing.html', status=status, job_id=job_id)


@app.route('/analysis-status/<job_id>')
def analysis_status(job_id: str):
    status = load_job_status(job_id)
    if not status:
        return jsonify({'error': 'No analysis job found.'}), 404
    return jsonify(status)


@app.route('/analysis-retry/<job_id>')
def analysis_retry(job_id: str):
    status = load_job_status(job_id)
    if not status:
        return 'No analysis job is available to retry.', 404

    status.update({
        'state': 'queued',
        'stage': 'Queued',
        'percent': 0,
        'eta_seconds': None,
        'error': None,
        'updated_at': now_iso(),
        'completed_at': None,
        'logs': [f"[{now_iso()}] Retry requested for {status.get('filename', 'uploaded file')}"],
    })
    save_job_status(job_id, status)
    start_analysis_job(job_id, status['stored_path'], status.get('filename', 'uploaded_artifact.bin'))
    return redirect(url_for('analyzing', job_id=job_id))

@app.route('/export')
@app.route('/export/<analysis_id>')
def export_report(analysis_id: str | None = None):
    analysis = load_analysis(analysis_id)
    if not analysis:
        return jsonify({'error': 'No analysis available for that file. Upload a file and open its dashboard first.'}), 404

    html_content = render_report_html(analysis)
    pdf_buffer = BytesIO()
    pisa_status = pisa.CreatePDF(BytesIO(html_content.encode('utf-8')), dest=pdf_buffer)

    if pisa_status.err:
        return jsonify({'error': 'Failed to create report'}), 500

    pdf_buffer.seek(0)
    response = make_response(pdf_buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="Forensic_Report_{analysis["analysis_id"][:12]}.pdf"'
    return response


@app.route('/report')
@app.route('/report/<analysis_id>')
def report_page(analysis_id: str | None = None):
    analysis = load_analysis(analysis_id)
    if not analysis:
        return 'No file-specific analysis is available. Upload a file and open its dashboard first.', 404
    return render_report_html(analysis)

if __name__ == '__main__':
    print("[SYSTEM] Activating evidence-driven forensic analysis engine...")
    app.run(debug=True, port=5000)