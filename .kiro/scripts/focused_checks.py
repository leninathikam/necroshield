"""Fixed check commands for Kiro hooks; event stdin never becomes executable text."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    if len(sys.argv) != 2 or sys.argv[1] not in {"backend", "frontend"}:
        print("Usage: python .kiro/scripts/focused_checks.py backend|frontend", file=sys.stderr)
        return 2
    target = sys.argv[1]
    run_dir = root / ".cache" / "kiro-checks" / uuid4().hex
    temp_dir = run_dir / "tmp"
    temp_dir.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(TEMP=str(temp_dir), TMP=str(temp_dir), TMPDIR=str(temp_dir))
    if target == "backend":
        interpreter = root / "backend" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not interpreter.is_file():
            print("Backend environment missing. Run python manage.py setup first.", file=sys.stderr)
            return 127
        command = [str(interpreter), "-m", "pytest", "-q", "--basetemp", str(run_dir / "pytest"),
                   "tests/test_policy.py", "tests/test_phase1.py", "tests/test_independent_review.py"]
        working_directory = root / "backend"
    else:
        command = ["npm.cmd" if os.name == "nt" else "npm", "--prefix", str(root / "frontend"), "run", "typecheck"]
        working_directory = root
    try:
        return subprocess.run(command, cwd=working_directory, env=environment,
                              check=False, timeout=110).returncode
    except FileNotFoundError as exc:
        print(f"Check prerequisite unavailable: {exc.filename}", file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired:
        print("Focused check exceeded 110 seconds.", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
