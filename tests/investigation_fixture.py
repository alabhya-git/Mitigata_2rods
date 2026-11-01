"""Owned integration targets and a clearly fake Anthropic-protocol controller."""

import argparse
import io
import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", action="store_true")
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body, kind="text/html"):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                return self.respond(200, "ok")
            if args.controller:
                return self.respond(404, "not found")
            if self.path == "/":
                return self.respond(
                    200,
                    '<a href="/client.zip">client artifact</a><a href="http://vault.lab:8000/vault">unlisted application</a><a href="http://172.31.248.11:8000/escape">unapproved address</a><script src="/client.js"></script><p>Another clue mentions agent-next.</p><form method="GET" action="/echo"><input name="q"></form>',
                )
            if self.path.startswith("/echo"):
                from urllib.parse import parse_qs, urlsplit

                value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
                return self.respond(200, "<div>" + value + "</div>")
            if self.path == "/client.js":
                return self.respond(
                    200,
                    "fetch('/render-data').then(r=>r.json()).then(d=>document.body.dataset.challenge=d.hidden_code)",
                    "application/javascript",
                )
            if self.path == "/render-data":
                return self.respond(
                    200, json.dumps({"hidden_code": "RENDERED{owned_js_route_72}"}), "application/json"
                )
            if self.path == "/agent-next":
                return self.respond(200, "challenge_code: INVESTIGATED{owned_model_tool_43}")
            if self.path == "/vault":
                return self.respond(200, "SHADOW{owned_same_ip_vhost_89}")
            if self.path == "/.git/HEAD":
                return self.respond(200, "ref: refs/heads/main\n", "text/plain")
            if self.path == "/config.json":
                return self.respond(
                    200, json.dumps({"api_key": "controlled-integration-secret"}), "application/json"
                )
            if self.path == "/client.zip":
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr(
                        "../../never-extract.txt", "hidden_code: ARTIFACT{owned_archive_member_21}"
                    )
                return self.respond(200, output.getvalue(), "application/octet-stream")
            return self.respond(404, "not found")

        def do_POST(self):
            if not args.controller or self.path != "/v1/messages":
                return self.respond(404, "not found")
            if self.headers.get("Authorization") != "Bearer owned-protocol-fixture-token-123456789":
                return self.respond(401, "denied")
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            model_tools = {t["name"] for t in data.get("tools", [])}
            content = [
                {"type": "text", "text": "This is an injected protocol test, not a real Claude inference."}
            ]
            initial = data["messages"][-1]["content"]
            if isinstance(initial, str) and "inspect_http" in model_tools:
                content = [
                    {
                        "type": "tool_use",
                        "id": "fixture-" + str(threading.get_ident()),
                        "name": "inspect_http",
                        "input": {"url": "http://172.31.248.10:8000/agent-next"},
                    }
                ]
            Path("/audit").mkdir(exist_ok=True)
            with Path("/audit/controller-calls.jsonl").open("a") as stream:
                stream.write(json.dumps({"model": data["model"], "mock": True}) + "\n")
            return self.respond(
                200,
                json.dumps({"content": content, "usage": {"input_tokens": 1000, "output_tokens": 100}}),
                "application/json",
            )

    ThreadingHTTPServer(("0.0.0.0", 8090 if args.controller else 8000), Handler).serve_forever()


if __name__ == "__main__":
    main()
