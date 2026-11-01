"""Only used on the owned, isolated integration-test Docker network."""

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    log = Path("/audit") / (args.label + ".jsonl")
    log.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            with lock, log.open("a") as stream:
                stream.write(
                    json.dumps({"path": self.path, "peer": self.client_address[0], "time": time.time()})
                    + "\n"
                )
            status, headers, body = 200, {}, ""
            if self.path == "/health":
                body = "ok"
            elif self.path == "/":
                body = '<a href="/configuration">configuration</a><a href="/redirect">redirect</a><a href="http://172.31.248.11:8000/escape">outside</a>'
            elif self.path == "/configuration":
                body = "SECRET=owned-synthetic-integration-value\n"
            elif self.path == "/redirect":
                status, headers = 302, {"Location": "http://172.31.248.11:8000/redirect-escape"}
            else:
                status, body = 404, "not found"
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()


if __name__ == "__main__":
    main()
