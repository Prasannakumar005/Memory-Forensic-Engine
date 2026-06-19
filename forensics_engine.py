from __future__ import annotations

import json
from pathlib import Path

from analysis_engine import analyze_file


def parse_and_store_mem_dump(dump_path):
    path = Path(dump_path)
    if not path.exists():
        return False

    analysis = analyze_file(str(path), original_filename=path.name)
    analysis_dir = path.parent / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    analysis_path = analysis_dir / f"{analysis['analysis_id']}.json"
    analysis_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    return analysis