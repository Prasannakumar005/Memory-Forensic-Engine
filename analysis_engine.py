from __future__ import annotations

import hashlib
import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yara = None


MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"EVF\t\r\n\xff\x00", "EWF forensic image"),
]

IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ip": re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    "url": re.compile(r"\bhttps?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[A-Za-z0-9_\\\- ]+", re.IGNORECASE),
    "windows_path": re.compile(r"\b[A-Za-z]:\\[^\r\n\t\"'<>|]{2,}"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}

SUSPICIOUS_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "Process injection",
        "family": None,
        "category": "code_injection",
        "patterns": [
            r"CreateRemoteThread",
            r"WriteProcessMemory",
            r"VirtualAllocEx",
            r"NtWriteVirtualMemory",
            r"QueueUserAPC",
            r"SetThreadContext",
        ],
    },
    {
        "name": "Credential dumping",
        "family": "Mimikatz",
        "category": "credential_access",
        "patterns": [r"mimikatz", r"MiniDumpWriteDump", r"sekurlsa", r"lsass"],
    },
    {
        "name": "Encoded PowerShell execution",
        "family": None,
        "category": "execution",
        "patterns": [r"powershell", r"-enc", r"FromBase64String", r"IEX", r"Invoke-Expression"],
    },
    {
        "name": "Persistence via autoruns",
        "family": None,
        "category": "persistence",
        "patterns": [r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", r"RunOnce", r"Scheduled Task", r"schtasks", r"Services\\"],
    },
    {
        "name": "Network beaconing",
        "family": None,
        "category": "network",
        "patterns": [r"cmd\.exe /c", r"curl ", r"wget ", r"nc\.exe", r"bitsadmin", r"ftp://"],
    },
]

ProgressCallback = Callable[[dict[str, Any]], None]


def report_progress(progress_callback: ProgressCallback | None, stage: str, percent: int, log: str | None = None, status: str = "running") -> None:
    if progress_callback is None:
        return
    progress_callback({"stage": stage, "percent": max(0, min(100, percent)), "log": log, "status": status})


def analyze_file(file_path: str, volatility_root: str | None = None, yara_rule_dirs: list[str] | None = None, progress_callback: ProgressCallback | None = None, original_filename: str | None = None) -> dict[str, Any]:
    path = Path(file_path)
    data = path.read_bytes()

    report_progress(progress_callback, "Detecting File Type...", 5, f"Loaded {path.name} for inspection.")

    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    report_progress(progress_callback, "Calculating Hashes...", 15, "Computed MD5, SHA1, and SHA256 values from the uploaded file.")

    file_type = detect_file_type(path, data)
    report_progress(progress_callback, "Extracting Metadata...", 20, f"Detected file type as {file_type['detected']}.")
    metadata = collect_metadata(path)
    strings = extract_strings(data)
    entropy = calculate_entropy(data)

    report_progress(progress_callback, "Running Malware Analysis...", 35, "Scanning extracted content for suspicious signatures and entropy anomalies.")
    iocs = extract_iocs(strings, data)

    report_progress(progress_callback, "Running YARA Scan...", 45, "Evaluating YARA rules against the uploaded file.")
    yara_matches = scan_yara(path, yara_rule_dirs or [])
    suspicious_indicators, signature_matches, family_name = detect_signatures(strings, data, entropy, yara_matches)

    report_progress(progress_callback, "Extracting Indicators of Compromise (IOC)...", 55, f"Extracted {len(iocs)} potential indicator(s) from the artifact.")

    memory_analysis = {
        "is_memory_dump": False,
        "plugins": {},
        "processes": [],
        "network_connections": [],
        "suspicious_processes": [],
        "hidden_processes": [],
        "code_injection": [],
        "persistence": [],
        "timeline_events": [],
        "summary": ["No evidence found."],
        "status": "No evidence found.",
    }

    if is_memory_dump(path, file_type, data):
        report_progress(progress_callback, "Running Memory Analysis (if applicable)...", 68, "Memory dump detected. Launching Volatility3 plugins.")
        memory_analysis = analyze_memory_dump(path, volatility_root, progress_callback=progress_callback)
    else:
        report_progress(progress_callback, "Running Memory Analysis (if applicable)...", 68, "Memory analysis skipped because the artifact is not a memory dump.")

    report_progress(progress_callback, "Building Attack Timeline...", 85, "Correlating timestamps, process activity, and indicators into a timeline.")
    timeline = build_timeline(metadata, memory_analysis)
    findings = build_findings(
        file_type=file_type,
        metadata=metadata,
        hashes=hashes,
        strings=strings,
        entropy=entropy,
        iocs=iocs,
        yara_matches=yara_matches,
        suspicious_indicators=suspicious_indicators,
        signature_matches=signature_matches,
        family_name=family_name,
        memory_analysis=memory_analysis,
    )

    risk_score = calculate_risk_score(findings)
    severity = score_to_severity(risk_score, findings)
    malware_present = any(item["type"] in {"yara", "signature", "memory_injection", "hidden_process", "active_connection"} for item in findings)
    infection_status = "Infected" if malware_present else "No evidence found."
    persistence_status = "Observed" if any(item["type"] == "persistence" for item in findings) else "No evidence found."
    threat_active = any(item["type"] in {"active_connection", "suspicious_process", "code_injection"} for item in findings)

    evidence_collected = build_evidence_list(file_type, metadata, hashes, strings, entropy, iocs, yara_matches, memory_analysis)
    attack_indicators = [item["title"] for item in findings if item["type"] in {"yara", "signature", "memory_injection", "persistence", "hidden_process", "active_connection", "high_entropy", "ioc"}]
    suspicious_processes = memory_analysis.get("suspicious_processes", [])
    evidence_profile = build_evidence_profile(findings, memory_analysis)

    conclusion_points = build_conclusion_points(findings, malware_present, family_name, infection_status, persistence_status, threat_active, severity, risk_score)

    report_progress(progress_callback, "Generating Report...", 95, "Formatting evidence into report-ready sections.")

    analysis = {
        "analysis_id": hashes["sha256"],
        "source_file": str(path),
        "filename": original_filename or path.name,
        "stored_filename": path.name,
        "original_filename": original_filename or path.name,
        "file_type": file_type,
        "metadata": metadata,
        "hashes": hashes,
        "strings": {"count": strings["count"], "sample": strings["sample"]},
        "entropy": entropy,
        "iocs": iocs,
        "yara_matches": yara_matches,
        "signature_matches": signature_matches,
        "suspicious_indicators": suspicious_indicators,
        "memory_analysis": memory_analysis,
        "timeline": timeline,
        "evidence_collected": evidence_collected,
        "attack_indicators": attack_indicators,
        "suspicious_processes": suspicious_processes,
        "malware_present": malware_present,
        "malware_family": family_name,
        "infection_status": infection_status,
        "persistence_status": persistence_status,
        "threat_active": threat_active,
        "severity": severity,
        "risk_score": risk_score,
        "conclusion_points": conclusion_points,
        "recommended_actions": build_recommended_actions(malware_present, threat_active, memory_analysis, findings),
        "has_evidence": bool(findings or iocs or yara_matches or memory_analysis.get("processes")),
        "evidence_profile": evidence_profile,
    }

    report_progress(progress_callback, "Finalizing Results...", 100, "Analysis complete and ready for dashboard presentation.", status="complete")
    return analysis


def detect_file_type(path: Path, data: bytes) -> dict[str, Any]:
    suffix = path.suffix.lower()
    magic_type = None
    for prefix, label in MAGIC_SIGNATURES:
        if data.startswith(prefix):
            magic_type = label
            break

    mime_type = mimetypes.guess_type(path.name)[0]
    detected = magic_type or mime_type or "Unknown binary/text artifact"
    if suffix in {".dmp", ".mem", ".raw", ".vmem", ".pmem", ".lime"}:
        detected = "Memory dump"
    elif suffix == ".e01":
        detected = "EWF forensic image"
    elif suffix in {".json", ".log", ".txt", ".csv", ".xml", ".jsonl", ".md"}:
        detected = mime_type or "Text artifact"

    return {"detected": detected, "mime_type": mime_type or "unknown", "extension": suffix or "(none)", "magic": magic_type or "unknown"}


def collect_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {"size": stat.st_size, "created": to_iso(stat.st_ctime), "modified": to_iso(stat.st_mtime), "accessed": to_iso(stat.st_atime)}


def to_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def extract_strings(data: bytes, max_strings: int = 2000) -> dict[str, Any]:
    pattern = re.compile(rb"[ -~]{4,}")
    sample: list[str] = []
    count = 0
    for match in pattern.finditer(data):
        count += 1
        if len(sample) < max_strings:
            sample.append(match.group(0).decode("utf-8", errors="ignore"))
    return {"count": count, "sample": sample}


def extract_iocs(strings: dict[str, Any], data: bytes) -> list[dict[str, Any]]:
    haystack = "\n".join(strings.get("sample", []))
    haystack += "\n" + data.decode("utf-8", errors="ignore")
    seen: set[tuple[str, str]] = set()
    iocs: list[dict[str, Any]] = []

    for ioc_type, pattern in IOC_PATTERNS.items():
        for value in pattern.findall(haystack):
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "description": evidence_description_for_ioc(ioc_type)})

    return iocs


def evidence_description_for_ioc(ioc_type: str) -> str:
    descriptions = {
        "ip": "Observed IP indicator in extracted evidence.",
        "url": "Observed URL indicator in extracted evidence.",
        "domain": "Observed domain indicator in extracted evidence.",
        "email": "Observed email indicator in extracted evidence.",
        "registry": "Observed registry path indicator in extracted evidence.",
        "windows_path": "Observed Windows path indicator in extracted evidence.",
        "sha256": "Observed SHA-256-like indicator in extracted evidence.",
        "sha1": "Observed SHA-1-like indicator in extracted evidence.",
        "md5": "Observed MD5-like indicator in extracted evidence.",
    }
    return descriptions.get(ioc_type, "Observed indicator in extracted evidence.")


def scan_yara(path: Path, yara_rule_dirs: list[str]) -> list[dict[str, Any]]:
    if yara is None:
        return []

    rule_files: list[Path] = []
    for directory in yara_rule_dirs:
        base = Path(directory)
        if base.exists():
            rule_files.extend(base.rglob("*.yar"))
            rule_files.extend(base.rglob("*.yara"))

    if not rule_files:
        default_dirs = [Path.cwd() / "rules", Path.cwd() / "yara", path.parent]
        for base in default_dirs:
            if base.exists():
                rule_files.extend(base.rglob("*.yar"))
                rule_files.extend(base.rglob("*.yara"))

    if not rule_files:
        return []

    try:
        rules = yara.compile(filepaths={f"rule_{index}": str(rule_file) for index, rule_file in enumerate(rule_files)})
        matches = rules.match(str(path))
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    for match in matches:
        results.append({"rule": match.rule, "namespace": getattr(match, "namespace", None), "tags": list(getattr(match, "tags", []) or []), "meta": dict(getattr(match, "meta", {}) or {})})
    return results


def detect_signatures(strings: dict[str, Any], data: bytes, entropy: float, yara_matches: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    sample_blob = "\n".join(strings.get("sample", [])) + "\n" + data.decode("utf-8", errors="ignore")

    suspicious_indicators: list[dict[str, Any]] = []
    signature_matches: list[dict[str, Any]] = []
    family_name: str | None = None

    for signature in SUSPICIOUS_SIGNATURES:
        hits = [pattern for pattern in signature["patterns"] if re.search(pattern, sample_blob, re.IGNORECASE)]
        if hits:
            signature_matches.append({"name": signature["name"], "category": signature["category"], "family": signature["family"], "evidence": hits})
            suspicious_indicators.append({"title": signature["name"], "evidence": ", ".join(hits), "category": signature["category"]})
            if signature["family"] and not family_name:
                family_name = signature["family"]

    if entropy >= 7.2:
        suspicious_indicators.append({"title": "High entropy content", "evidence": f"Entropy score {entropy:.2f}", "category": "packing"})

    if yara_matches:
        suspicious_indicators.append({"title": "YARA match", "evidence": ", ".join(match["rule"] for match in yara_matches), "category": "yara"})
        if not family_name:
            family_name = yara_matches[0]["rule"]

    return suspicious_indicators, signature_matches, family_name


def is_memory_dump(path: Path, file_type: dict[str, Any], data: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".dmp", ".mem", ".raw", ".vmem", ".pmem", ".lime"}:
        return True
    if file_type.get("detected") == "Memory dump":
        return True
    if data.startswith(b"\x00" * 16) and path.stat().st_size > 5 * 1024 * 1024:
        return True
    return False


def locate_volatility_root(explicit_root: str | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit_root:
        candidates.append(Path(explicit_root))

    env_root = os.getenv("VOLATILITY3_PATH")
    if env_root:
        candidates.append(Path(env_root))

    home = Path.home()
    candidates.extend([
        home / "downloads" / "volatility3-develop" / "volatility3-develop",
        home / "Downloads" / "volatility3-develop" / "volatility3-develop",
        Path(r"C:\Users\acer\downloads\volatility3-develop\volatility3-develop"),
        Path(r"C:\Users\acer\Downloads\volatility3-develop\volatility3-develop"),
    ])

    for candidate in candidates:
        if candidate.exists() and (candidate / "vol.py").exists():
            return candidate

    vol_py = shutil.which("vol.py")
    if vol_py:
        return Path(vol_py).parent

    return None


def analyze_memory_dump(path: Path, volatility_root: str | None = None, progress_callback: ProgressCallback | None = None) -> dict[str, Any]:
    root = locate_volatility_root(volatility_root)
    if root is None:
        report_progress(progress_callback, "Running Memory Analysis (if applicable)...", 72, "Volatility3 not available on this system.")
        return {
            "is_memory_dump": True,
            "plugins": {},
            "processes": [],
            "network_connections": [],
            "suspicious_processes": [],
            "hidden_processes": [],
            "code_injection": [],
            "persistence": [],
            "timeline_events": [],
            "summary": ["Volatility3 not available."] ,
            "status": "No evidence found.",
        }

    plugins = ["windows.info", "windows.pslist", "windows.pstree", "windows.netscan", "windows.malfind", "windows.cmdline", "windows.dlllist", "windows.handles"]
    plugin_results: dict[str, Any] = {}
    for index, plugin in enumerate(plugins, start=1):
        percent = 68 + int((index / len(plugins)) * 12)
        report_progress(progress_callback, "Running Memory Analysis (if applicable)...", percent, f"Running Volatility3 plugin: {plugin}.")
        plugin_results[plugin] = run_volatility_plugin(root, path, plugin)

    report_progress(progress_callback, "Running Memory Analysis (if applicable)...", 82, "Memory plugins completed. Summarizing results.")
    return summarize_memory_analysis(plugin_results)


def run_volatility_plugin(root: Path, dump_path: Path, plugin: str) -> dict[str, Any]:
    command = [sys.executable, "vol.py", "-f", str(dump_path), "-r", "json", plugin]
    try:
        completed = subprocess.run(command, cwd=str(root), capture_output=True, text=True, timeout=180, check=False)
    except Exception as exc:
        return {"error": str(exc), "rows": []}

    raw_output = completed.stdout.strip()
    if not raw_output:
        return {"error": completed.stderr.strip() or f"No output returned for {plugin}", "rows": []}

    try:
        parsed = json.loads(raw_output)
    except Exception:
        return {"error": completed.stderr.strip() or "Failed to parse Volatility JSON", "rows": [], "raw": raw_output}

    return {"raw": parsed, "rows": normalize_volatility_rows(parsed), "stderr": completed.stderr.strip(), "returncode": completed.returncode}


def normalize_volatility_rows(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        rows: list[dict[str, Any]] = []
        for item in payload:
            rows.extend(normalize_volatility_rows(item))
        return rows
    if isinstance(payload, dict):
        if "columns" in payload and "rows" in payload:
            columns = payload.get("columns") or []
            normalized_rows: list[dict[str, Any]] = []
            for row in payload.get("rows", []):
                if isinstance(row, dict):
                    normalized_rows.append(row)
                elif isinstance(row, list):
                    normalized_rows.append({str(columns[index]): row[index] if index < len(row) else None for index in range(len(columns))})
            return normalized_rows
        if "data" in payload:
            return normalize_volatility_rows(payload["data"])
        return [payload]
    return []


def summarize_memory_analysis(plugin_results: dict[str, Any]) -> dict[str, Any]:
    pslist_rows = plugin_results.get("windows.pslist", {}).get("rows", [])
    pstree_rows = plugin_results.get("windows.pstree", {}).get("rows", [])
    netscan_rows = plugin_results.get("windows.netscan", {}).get("rows", [])
    malfind_rows = plugin_results.get("windows.malfind", {}).get("rows", [])
    cmdline_rows = plugin_results.get("windows.cmdline", {}).get("rows", [])
    dlllist_rows = plugin_results.get("windows.dlllist", {}).get("rows", [])
    handles_rows = plugin_results.get("windows.handles", {}).get("rows", [])

    processes: dict[int, dict[str, Any]] = {}
    for row in pslist_rows:
        pid = to_int(_lookup(row, "UniqueProcessId", "PID", "Pid"))
        if pid is None:
            continue
        processes[pid] = {
            "pid": pid,
            "ppid": to_int(_lookup(row, "InheritedFromUniqueProcessId", "PPID", "ParentPid")) or 0,
            "name": str(_lookup(row, "ImageFileName", "Name", "Process") or "Unknown"),
            "create_time": _lookup(row, "CreateTime", "StartTime", "Created", "Time"),
            "offset": str(_lookup(row, "Offset(V)", "Offset", "Address") or ""),
            "threads": to_int(_lookup(row, "ThreadCount", "Threads")) or 0,
            "handles": to_int(_lookup(row, "HandleCount", "Handles")) or 0,
            "status": "Clean",
            "evidence": [],
        }

    cmdline_by_pid = {
        pid: str(row.get("CommandLine") or row.get("CmdLine") or row.get("Command") or "")
        for row in cmdline_rows
        if (pid := to_int(_lookup(row, "UniqueProcessId", "PID", "Pid"))) is not None
    }

    dlls_by_pid: dict[int, list[str]] = {}
    for row in dlllist_rows:
        pid = to_int(_lookup(row, "UniqueProcessId", "PID", "Pid"))
        if pid is None:
            continue
        dll_name = str(_lookup(row, "FullDllName", "DllName", "Name", "Path") or "").strip()
        if dll_name:
            dlls_by_pid.setdefault(pid, []).append(dll_name)

    malfind_pids: set[int] = set()
    for row in malfind_rows:
        pid = to_int(_lookup(row, "UniqueProcessId", "PID", "Pid", "ProcessId"))
        if pid is None:
            continue
        malfind_pids.add(pid)
        if pid in processes:
            processes[pid]["status"] = "Suspicious"
            processes[pid]["evidence"].append("Volatility malfind reported injected or hidden memory regions.")

    suspicious_processes: list[dict[str, Any]] = []
    code_injection: list[dict[str, Any]] = []
    persistence: list[dict[str, Any]] = []
    network_connections: list[dict[str, Any]] = []
    timeline_events: list[dict[str, Any]] = []
    hidden_processes: list[dict[str, Any]] = []

    observed_pids: set[int] = set(processes.keys())
    for row in pstree_rows:
        pid = to_int(_lookup(row, "UniqueProcessId", "PID", "Pid"))
        if pid is not None:
            observed_pids.add(pid)

    for row in netscan_rows:
        pid = to_int(_lookup(row, "OwningProcess", "UniqueProcessId", "PID", "Pid"))
        if pid is not None:
            observed_pids.add(pid)
        local = _lookup(row, "LocalAddr", "LocalAddress", "Local")
        remote = _lookup(row, "ForeignAddr", "RemoteAddr", "RemoteAddress", "Remote")
        state = str(_lookup(row, "State", "ConnState") or "")
        if remote or state:
            network_connections.append({"pid": pid, "local": str(local or ""), "remote": str(remote or ""), "state": state or "Unknown", "description": "Active network connection observed in Volatility netscan output."})

    for row in malfind_rows:
        pid = to_int(_lookup(row, "UniqueProcessId", "PID", "Pid", "ProcessId"))
        if pid is None:
            continue
        process_name = processes.get(pid, {}).get("name", str(_lookup(row, "Process", "ImageFileName") or "Unknown"))
        suspicious_processes.append({"pid": pid, "name": process_name, "reason": "malfind flagged suspicious memory regions"})
        code_injection.append({"pid": pid, "name": process_name, "evidence": "Volatility malfind output showed anomalous executable memory content."})

    for row in handles_rows:
        handle_name = str(_lookup(row, "Name", "Object", "Handle", "Type") or "")
        if re.search(r"\\(?:Run|RunOnce|Services|Scheduled Tasks?|Startup)\\", handle_name, re.IGNORECASE):
            persistence.append({"pid": to_int(_lookup(row, "UniqueProcessId", "PID", "Pid")), "name": str(_lookup(row, "ImageFileName", "Process") or "Unknown"), "artifact": handle_name, "description": "Registry or persistence-related handle observed in Volatility handles output."})

    hidden_pids = observed_pids - set(processes.keys())
    for pid in sorted(hidden_pids):
        hidden_processes.append({"pid": pid, "name": "Unknown", "description": "Process evidence appeared in non-pslist Volatility output but not in pslist."})

    for pid, process in processes.items():
        command_line = cmdline_by_pid.get(pid, "")
        if command_line:
            process["command_line"] = command_line
            if re.search(r"-enc|FromBase64String|IEX|Invoke-Expression", command_line, re.IGNORECASE):
                process["status"] = "Suspicious"
                process["evidence"].append("Suspicious encoded command line observed in Volatility cmdline output.")
        if dlls_by_pid.get(pid):
            process["dlls"] = dlls_by_pid[pid]
        if pid in malfind_pids and process["status"] != "Suspicious":
            process["status"] = "Suspicious"
        if process["status"] == "Suspicious":
            suspicious_processes.append({"pid": pid, "name": process["name"], "reason": "; ".join(process.get("evidence", [])) or "Volatility output marked this process as suspicious."})
        if process.get("create_time"):
            timeline_events.append({"timestamp": str(process["create_time"]), "event_type": "Process creation", "description": f"Process {process['name']} (PID {pid}) appeared in Volatility pslist.", "evidence": f"pslist create time for PID {pid}"})

    for row in netscan_rows:
        local = _lookup(row, "LocalAddr", "LocalAddress", "Local")
        remote = _lookup(row, "ForeignAddr", "RemoteAddr", "RemoteAddress", "Remote")
        state = _lookup(row, "State", "ConnState")
        if remote or state:
            timeline_events.append({"timestamp": str(_lookup(row, "CreateTime", "Time", "Timestamp") or "No evidence found."), "event_type": "Network connection", "description": f"{local or 'local'} -> {remote or 'unknown'} ({state or 'Unknown'}).", "evidence": "Volatility netscan output."})

    summary_lines: list[str] = []
    if suspicious_processes:
        summary_lines.append(f"{len(suspicious_processes)} suspicious process entries identified from Volatility outputs.")
    if network_connections:
        summary_lines.append(f"{len(network_connections)} network connection entries identified from netscan.")
    if code_injection:
        summary_lines.append(f"{len(code_injection)} code injection indicators observed via malfind.")
    if persistence:
        summary_lines.append(f"{len(persistence)} persistence indicators observed in handle evidence.")
    if hidden_processes:
        summary_lines.append(f"{len(hidden_processes)} hidden process candidates observed outside pslist.")

    return {"is_memory_dump": True, "plugins": plugin_results, "processes": list(processes.values()), "network_connections": network_connections, "suspicious_processes": suspicious_processes, "hidden_processes": hidden_processes, "code_injection": code_injection, "persistence": persistence, "timeline_events": timeline_events, "summary": summary_lines or ["No evidence found."], "status": "Evidence found." if summary_lines else "No evidence found."}


def build_timeline(metadata: dict[str, Any], memory_analysis: dict[str, Any]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    if metadata.get("created"):
        timeline.append({"timestamp": metadata["created"], "event_type": "File creation", "description": "File creation timestamp from filesystem metadata.", "evidence": "Filesystem metadata"})
    if metadata.get("modified"):
        timeline.append({"timestamp": metadata["modified"], "event_type": "File modification", "description": "File modification timestamp from filesystem metadata.", "evidence": "Filesystem metadata"})

    timeline.extend(memory_analysis.get("timeline_events", []))

    if not timeline:
        timeline.append({"timestamp": "No evidence found.", "event_type": "Timeline", "description": "No timestamped evidence was available from the uploaded file.", "evidence": "No evidence found."})

    return timeline


def build_findings(*, file_type: dict[str, Any], metadata: dict[str, Any], hashes: dict[str, str], strings: dict[str, Any], entropy: float, iocs: list[dict[str, Any]], yara_matches: list[dict[str, Any]], suspicious_indicators: list[dict[str, Any]], signature_matches: list[dict[str, Any]], family_name: str | None, memory_analysis: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in suspicious_indicators:
        findings.append({"type": item["category"], "title": item["title"], "evidence": item["evidence"]})

    for ioc in iocs:
        findings.append({"type": "ioc", "title": f"IOC {ioc['type']}", "evidence": f"{ioc['value']} ({ioc['description']})"})

    for match in yara_matches:
        findings.append({"type": "yara", "title": f"YARA match: {match['rule']}", "evidence": json.dumps(match, sort_keys=True)})

    for match in signature_matches:
        findings.append({"type": "signature", "title": match["name"], "evidence": ", ".join(match["evidence"]), "family": match.get("family")})

    for proc in memory_analysis.get("suspicious_processes", []):
        findings.append({"type": "suspicious_process", "title": f"Suspicious process {proc['name']} (PID {proc['pid']})", "evidence": proc["reason"]})

    for proc in memory_analysis.get("hidden_processes", []):
        findings.append({"type": "hidden_process", "title": f"Hidden process candidate PID {proc['pid']}", "evidence": proc["description"]})

    for item in memory_analysis.get("code_injection", []):
        findings.append({"type": "memory_injection", "title": f"Code injection indicator in PID {item['pid']}", "evidence": item["evidence"]})

    for item in memory_analysis.get("network_connections", []):
        findings.append({"type": "active_connection", "title": f"Network connection PID {item.get('pid', 'unknown')}", "evidence": json.dumps(item, sort_keys=True)})

    for item in memory_analysis.get("persistence", []):
        findings.append({"type": "persistence", "title": "Persistence indicator", "evidence": json.dumps(item, sort_keys=True)})

    if entropy >= 7.2:
        findings.append({"type": "high_entropy", "title": "High entropy content", "evidence": f"Entropy score {entropy:.2f}"})

    findings.append({"type": "file_type", "title": "File type detected", "evidence": file_type.get("detected", "Unknown")})
    findings.append({"type": "metadata", "title": "Filesystem metadata collected", "evidence": json.dumps(metadata, sort_keys=True)})
    findings.append({"type": "hashes", "title": "Cryptographic hashes collected", "evidence": json.dumps(hashes, sort_keys=True)})
    findings.append({"type": "strings", "title": "Strings extracted", "evidence": f"{strings['count']} printable strings extracted."})

    if family_name:
        findings.append({"type": "family", "title": "Candidate family identified", "evidence": family_name})

    return findings


def build_evidence_list(file_type: dict[str, Any], metadata: dict[str, Any], hashes: dict[str, str], strings: dict[str, Any], entropy: float, iocs: list[dict[str, Any]], yara_matches: list[dict[str, Any]], memory_analysis: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = [
        {"section": "File Type", "value": file_type.get("detected", "Unknown"), "evidence": file_type.get("magic", "unknown")},
        {"section": "Metadata", "value": f"Size {metadata.get('size')} bytes", "evidence": json.dumps(metadata, sort_keys=True)},
        {"section": "Hashes", "value": hashes["sha256"], "evidence": json.dumps(hashes, sort_keys=True)},
        {"section": "Strings", "value": str(strings["count"]), "evidence": "Printable strings extracted from file bytes."},
        {"section": "Entropy", "value": f"{entropy:.4f}", "evidence": "Calculated from the file byte distribution."},
    ]

    for ioc in iocs:
        evidence.append({"section": f"IOC: {ioc['type']}", "value": ioc["value"], "evidence": ioc["description"]})

    for match in yara_matches:
        evidence.append({"section": "YARA", "value": match["rule"], "evidence": json.dumps(match, sort_keys=True)})

    if memory_analysis.get("processes"):
        evidence.append({"section": "Volatility pslist", "value": str(len(memory_analysis["processes"])), "evidence": "Observed processes in Volatility pslist output."})

    return evidence


def build_evidence_profile(findings: list[dict[str, Any]], memory_analysis: dict[str, Any]) -> dict[str, Any]:
    malicious_types = {"yara", "signature", "memory_injection", "hidden_process", "active_connection"}
    suspicious_types = {"ioc", "high_entropy", "persistence", "code_injection", "suspicious_process"}

    malicious = sum(1 for finding in findings if finding.get("type") in malicious_types)
    suspicious = sum(1 for finding in findings if finding.get("type") in suspicious_types)
    benign = 4 + sum(1 for proc in memory_analysis.get("processes", []) if proc.get("status") == "Clean")

    total = benign + suspicious + malicious
    if total <= 0:
        total = 1
        benign = 1

    return {
        "benign": benign,
        "suspicious": suspicious,
        "malicious": malicious,
        "total": total,
        "benign_percent": round((benign / total) * 100, 1),
        "suspicious_percent": round((suspicious / total) * 100, 1),
        "malicious_percent": round((malicious / total) * 100, 1),
    }


def calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    score = 0
    weights = {"yara": 35, "signature": 25, "memory_injection": 25, "hidden_process": 20, "active_connection": 15, "persistence": 15, "suspicious_process": 15, "code_injection": 20, "high_entropy": 10, "ioc": 5}
    for finding in findings:
        score += weights.get(finding["type"], 0)
    return min(score, 100)


def score_to_severity(score: int, findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No evidence found."
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def build_conclusion_points(findings: list[dict[str, Any]], malware_present: bool, family_name: str | None, infection_status: str, persistence_status: str, threat_active: bool, severity: str, risk_score: int) -> list[dict[str, Any]]:
    if not findings:
        return [{"text": "No evidence found.", "evidence": "The uploaded file did not produce actionable indicators."}]

    points = [
        {"text": f"Malware present: {'Yes' if malware_present else 'No' }.", "evidence": next((format_finding(f) for f in findings if f["type"] in {"yara", "signature", "memory_injection", "suspicious_process", "active_connection"}), "No evidence found.")},
        {"text": f"Malware family: {family_name if family_name else 'No evidence found.'}.", "evidence": family_name or "No evidence found."},
        {"text": f"Infection status: {infection_status}.", "evidence": next((format_finding(f) for f in findings if f["type"] in {"yara", "signature", "memory_injection"}), "No evidence found.")},
        {"text": f"Persistence status: {persistence_status}.", "evidence": next((format_finding(f) for f in findings if f["type"] == "persistence"), "No evidence found.")},
        {"text": f"Threat active: {'Yes' if threat_active else 'No'}.", "evidence": next((format_finding(f) for f in findings if f["type"] in {"active_connection", "suspicious_process", "memory_injection"}), "No evidence found.")},
        {"text": f"Severity: {severity}. Risk score: {risk_score}.", "evidence": next((format_finding(f) for f in findings if f["type"] in {"yara", "signature", "hidden_process", "persistence", "high_entropy"}), "No evidence found.")},
    ]
    return points


def build_recommended_actions(malware_present: bool, threat_active: bool, memory_analysis: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not findings:
        return [{"action": "No evidence found.", "evidence": "No actionable indicators were collected from the uploaded file."}]

    actions = [{"action": "Preserve the original artifact and acquisition chain.", "evidence": "Cryptographic hashes and filesystem metadata were collected."}]
    if malware_present:
        actions.append({"action": "Isolate the host and perform containment.", "evidence": "Malware indicators were observed in the uploaded file analysis."})
    if threat_active:
        actions.append({"action": "Inspect active processes and network endpoints immediately.", "evidence": "Active process or connection evidence was observed."})
    if memory_analysis.get("persistence"):
        actions.append({"action": "Review autoruns, services, and scheduled tasks.", "evidence": "Persistence indicators were observed in Volatility handles output."})
    if memory_analysis.get("code_injection"):
        actions.append({"action": "Examine injected memory regions and parent-child process chains.", "evidence": "Volatility malfind reported suspicious memory regions."})
    actions.append({"action": "Re-scan with organization-approved YARA rules and endpoint telemetry.", "evidence": "No invented findings were used; this recommendation is tied to collected evidence only."})
    return actions


def format_finding(finding: dict[str, Any]) -> str:
    return f"{finding['title']}: {finding['evidence']}"


def _lookup(row: dict[str, Any], *keys: str) -> Any:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def to_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(str(value).strip())
    except Exception:
        return None