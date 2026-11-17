"""One trusted fixture per process; no dynamic imports from scenario content."""

import json
import socket
import sys

from .engine import execute_pair
from .scenarios import SCENARIOS


def _deny_socket(*args, **kwargs):
    raise PermissionError("Synthetic workers have no network capability")


def main() -> None:
    if sys.platform != "win32":
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    socket.socket = _deny_socket
    socket.create_connection = _deny_socket
    socket.getaddrinfo = _deny_socket
    payload = sys.stdin.buffer.read(1025)
    if len(payload) > 1024:
        raise ValueError("Worker request exceeded input budget")
    request = json.loads(payload)
    if set(request) != {"scenario_id"} or request["scenario_id"] not in SCENARIOS:
        raise ValueError("Only registered fixture identifiers may execute")
    pair = execute_pair(SCENARIOS[request["scenario_id"]])
    sys.stdout.write(pair.model_dump_json())


if __name__ == "__main__":
    main()
