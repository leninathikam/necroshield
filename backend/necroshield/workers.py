"""Fresh interpreter workers with time, concurrency, and output budgets.

This contains trusted fixture code only. It is not an arbitrary-code sandbox.
Windows additionally receives a per-process memory/CPU Job Object limit; Unix
workers set rlimits. The worker disables Python socket creation at runtime.
"""

import ctypes
import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager

from .contracts import RunPair

WORKER_TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 256_000
_WORKERS = threading.BoundedSemaphore(2)


class WorkerFailure(RuntimeError):
    pass


@contextmanager
def _windows_job(process: subprocess.Popen):
    if sys.platform != "win32":
        yield
        return
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class IOCount(ctypes.Structure):
        _fields_ = [(field, ctypes.c_uint64) for field in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount",
                     "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IOCount),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        process.kill()
        raise WorkerFailure("Could not create worker resource boundary")
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x100 | 0x2  # kill-on-close, memory, CPU
    limits.BasicLimitInformation.PerProcessUserTimeLimit = 3 * 10_000_000
    limits.ProcessMemoryLimit = 256 * 1024 * 1024
    try:
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            process.kill()
            raise WorkerFailure("Could not configure worker resource limits")
        if not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
            process.kill()
            raise WorkerFailure("Could not assign worker resource limits")
        yield
    finally:
        kernel.CloseHandle(job)


def execute_pair_isolated(scenario_id: str) -> RunPair:
    if not _WORKERS.acquire(blocking=False):
        raise WorkerFailure("Arena worker capacity reached; retry shortly")
    try:
        # No production credentials or application database URL enter workers.
        # PYTHONPATH is unnecessary because the package is installed in the venv.
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "VIRTUAL_ENV"}}
        environment["PYTHONIOENCODING"] = "utf-8"
        with subprocess.Popen([sys.executable, "-I", "-m", "necroshield.worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as process:
            try:
                with _windows_job(process):
                    output, error = process.communicate(json.dumps({"scenario_id": scenario_id}).encode(),
                                                        timeout=WORKER_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.communicate()
                raise WorkerFailure("Fixture exceeded its wall-clock budget") from exc
            if process.returncode != 0:
                raise WorkerFailure("Fixture worker failed within its resource boundary")
            if len(output) > MAX_OUTPUT_BYTES:
                raise WorkerFailure("Fixture exceeded its evidence output budget")
            return RunPair.model_validate_json(output)
    finally:
        _WORKERS.release()
