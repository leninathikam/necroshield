"""A minimal reverse proxy that behaves like a platform load balancer for the purpose of testing the app:
it appends the address of the connecting client to X-Forwarded-For and forwards everything else, including
Host. Standard library only. Used by CI to run the deployment smoke test in proxied mode.

    python3 xff_proxy.py LISTEN_PORT http://127.0.0.1:UPSTREAM_PORT
"""

import http.client
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade"}


def append_forwarded_for(existing: str | None, client_ip: str) -> str:
    return f"{existing}, {client_ip}" if existing else client_ip


def make_server(listen_port: int, upstream: str, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    target = urllib.parse.urlsplit(upstream)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _forward(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP | {"x-forwarded-for"}}
            headers["X-Forwarded-For"] = append_forwarded_for(self.headers.get("x-forwarded-for"), self.client_address[0])
            conn = http.client.HTTPConnection(target.hostname, target.port, timeout=60)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in HOP_BY_HOP | {"content-length"}:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            finally:
                conn.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = _forward

        def log_message(self, *_args) -> None:  # keep CI logs readable
            pass

    return ThreadingHTTPServer((host, listen_port), Handler)


if __name__ == "__main__":
    make_server(int(sys.argv[1]), sys.argv[2]).serve_forever()
