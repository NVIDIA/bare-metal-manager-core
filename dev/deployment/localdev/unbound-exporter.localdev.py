#!/usr/bin/env python3
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


KEYS_DIR = os.environ.get("KEYS_DIR", "/etc/unbound/keys")
CONTROL_CONFIG = "/tmp/unbound-control-exporter.conf"


def write_control_config():
    with open(CONTROL_CONFIG, "w", encoding="utf-8") as config:
        config.write(
            f"""remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "{KEYS_DIR}/unbound_server.key"
    server-cert-file: "{KEYS_DIR}/unbound_server.pem"
    control-key-file: "{KEYS_DIR}/unbound_control.key"
    control-cert-file: "{KEYS_DIR}/unbound_control.pem"
"""
        )


def metric_name(name):
    return "unbound_" + re.sub(r"[^a-zA-Z0-9_]", "_", name)


def collect_metrics():
    write_control_config()
    output = subprocess.check_output(
        ["unbound-control", "-c", CONTROL_CONFIG, "stats_noreset"],
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )

    metrics = []
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            float(value)
        except ValueError:
            continue
        metrics.append(f"# TYPE {metric_name(key)} gauge")
        metrics.append(f"{metric_name(key)} {value}")

    return "\n".join(metrics) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/metrics", "/"):
            self.send_response(404)
            self.end_headers()
            return

        try:
            body = collect_metrics().encode()
            self.send_response(200)
        except Exception as error:
            body = f"# unbound exporter error: {error}\n".encode()
            self.send_response(503)

        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("UNBOUND_EXPORTER_PORT", "9167"))
    ThreadingHTTPServer(("", port), Handler).serve_forever()
