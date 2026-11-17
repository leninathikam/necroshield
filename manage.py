"""Small cross-platform entry point for the local NecroShield release."""

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
PYTHON = BACKEND / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
NPM = shutil.which("npm.cmd" if os.name == "nt" else "npm")


def run(command: list[str], cwd: Path) -> None:
    temporary = ROOT / ".cache/tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    environment = {**os.environ, "TEMP": str(temporary), "TMP": str(temporary)}
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def require_setup() -> None:
    if not NPM:
        raise SystemExit("Node.js/npm is required. Install it before running this command.")
    if not PYTHON.is_file() or not (FRONTEND / "node_modules").is_dir():
        raise SystemExit("Dependencies missing. Run: python manage.py setup")


def setup() -> None:
    if not NPM:
        raise SystemExit("Install Node.js (20.9 or newer) and npm first.")
    if not PYTHON.is_file():
        run([sys.executable, "-m", "venv", str(BACKEND / ".venv")], ROOT)
    uv = shutil.which("uv")
    if uv:
        if (BACKEND / "uv.lock").is_file():
            run([uv, "sync", "--locked", "--extra", "test", "--cache-dir", str(ROOT / ".cache/uv")], BACKEND)
        else:
            run([uv, "pip", "install", "--python", str(PYTHON), "--cache-dir", str(ROOT / ".cache/uv"), "-e", ".[test]"], BACKEND)
    else:
        if (BACKEND / "requirements.lock").is_file():
            run([str(PYTHON), "-m", "pip", "install", "--require-hashes", "-r", "requirements.lock"], BACKEND)
            run([str(PYTHON), "-m", "pip", "install", "--no-deps", "-e", "."], BACKEND)
        else:
            run([str(PYTHON), "-m", "pip", "install", "-e", ".[test]"], BACKEND)
    run([NPM, "ci" if (FRONTEND / "package-lock.json").exists() else "install"], FRONTEND)


def stop_owned_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        # Only the PID we just started; stop npm's Next.js descendants as well.
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def dev() -> None:
    require_setup()
    processes: list[subprocess.Popen] = []
    options = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
               else {"start_new_session": True})
    environment = {**os.environ, "NECROSHIELD_FRONTEND_ORIGIN": "http://127.0.0.1:3017",
                   "BACKEND_URL": "http://127.0.0.1:8017"}
    try:
        processes.append(subprocess.Popen([str(PYTHON), "-m", "uvicorn", "necroshield.main:app",
                                          "--host", "127.0.0.1", "--port", "8017"], cwd=BACKEND, env=environment, **options))
        processes.append(subprocess.Popen([NPM, "run", "dev"], cwd=FRONTEND, env=environment, **options))
        print("\nNecroShield: http://127.0.0.1:3017 | API: http://127.0.0.1:8017/docs", flush=True)
        print("Synthetic fixtures only. Press Ctrl+C to stop both services.", flush=True)
        while all(process.poll() is None for process in processes):
            time.sleep(0.25)
        failed = next((process.returncode for process in processes if process.poll() is not None), 1)
        if failed:
            raise SystemExit(failed)
    except KeyboardInterrupt:
        pass
    finally:
        for process in reversed(processes):
            stop_owned_process(process)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["setup", "dev", "test", "build", "benchmark", "e2e"])
    command = parser.parse_args().command
    if command == "setup":
        setup()
        return
    require_setup()
    if command == "dev":
        dev()
    elif command == "test":
        test_root = ROOT / ".cache/pytest"
        test_root.mkdir(parents=True, exist_ok=True)
        run([str(PYTHON), "-m", "pytest", "--basetemp", str(test_root / str(uuid4()))], BACKEND)
        run([NPM, "run", "typecheck"], FRONTEND)
    elif command == "build":
        run([NPM, "run", "build"], FRONTEND)
    elif command == "benchmark":
        run([str(PYTHON), "-m", "necroshield.cli", "--output", str(ROOT / "evidence/benchmark.json")], BACKEND)
    elif command == "e2e":
        run([NPM, "run", "test:e2e"], FRONTEND)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc
