"""Container entrypoint.

Hosting platforms mount persistent disks owned by root, which a non-root process cannot write.
This starts as root only long enough to give the data directory to the service user, drops to
that user (uid/gid 10001, no supplementary groups), checks the directory is writable, and then
execs uvicorn on the platform-assigned PORT. If started as non-root it skips the ownership step.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SERVICE_UID = SERVICE_GID = 10001


def main() -> None:
    db = Path(os.environ.get("NECROSHIELD_DB", "/data/necroshield.db"))
    data = db.parent
    if os.getuid() == 0:
        data.mkdir(parents=True, exist_ok=True)
        # Take over a dedicated data directory (a mounted disk), but never a shared one such as /tmp.
        shared = data.stat().st_mode & 0o002
        for path in ((db, Path(f"{db}-wal"), Path(f"{db}-shm"), Path(f"{db}-journal")) if shared
                     else (data, db, Path(f"{db}-wal"), Path(f"{db}-shm"), Path(f"{db}-journal"))):
            if path.exists():
                os.chown(path, SERVICE_UID, SERVICE_GID)
        os.setgroups([])
        os.setgid(SERVICE_GID)
        os.setuid(SERVICE_UID)
    if os.getuid() == 0:
        sys.exit("refusing to run the service as root")
    if not os.access(data, os.W_OK | os.X_OK):
        sys.exit(f"data directory {data} is not writable by uid {os.getuid()}")
    port = os.environ.get("PORT", "8017")
    if not port.isdigit():
        sys.exit(f"PORT must be a number, got {port!r}")
    # Client identity for rate limits comes from NecroShield's own guard (NECROSHIELD_PROXY_HOPS),
    # so uvicorn must not rewrite the peer address from forwarded headers.
    os.execvp(sys.executable, [sys.executable, "-m", "uvicorn", "necroshield.api.app:app_from_env", "--factory",
                               "--host", "0.0.0.0", "--port", port, "--no-proxy-headers", "--no-server-header"])


if __name__ == "__main__":
    main()
