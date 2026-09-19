"""Loopback metadata endpoints pinning the restored client to build 54261."""

import json
import os
import re
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

BUILD = "c91609c69ed2ab39d44039390a1be969"
CDN = "a838aeb3cda2e027e9c96bd9953944b3"
PRODUCT = "fac7680539cd51bc0a791a88ade3da21"
REGIONS = ("eu", "us", "kr", "tw", "cn")
VERSIONS = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|KeyRing!HEX:16|BuildId!DEC:4|VersionsName!STRING:0|ProductConfig!HEX:16\n"
VERSIONS += "".join(
    f"{r}|{BUILD}|{CDN}||54261|3.4.3.54261|{PRODUCT}\n" for r in REGIONS
)
CDNS = (
    "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0|ConfigPath!STRING:0\n"
)
CDNS += "".join(
    f"{r}|tpr/wow|127.0.0.1|http://127.0.0.1:8090/?maxhosts=4|\n" for r in REGIONS
)
MIRRORS = (
    "https://casc.wago.tools",
    "https://cdn.arctium.tools",
    "https://archive.wow.tools",
)
CACHE = Path(os.environ["WRATH_STATE"]) / "cache/casc/cdn"
ACTIVITY = {"data_requests": 0, "data_failures": 0}


def bind_catalog(server, target):
    from catalog import validate_catalog
    catalog = validate_catalog(target)
    server.build_key = catalog['build_key']
    server.build_config = catalog['config']
    server.versions = VERSIONS.replace(BUILD, server.build_key)
    return catalog


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/tpr/wow/"):
            self.serve_cdn(path)
            return
        content = {
            "/versions": getattr(self.server, "versions", VERSIONS),
            "/cdns": CDNS,
            "/health": json.dumps(
                {"build": "3.4.3.54261", "product": "wow_classic", **ACTIVITY}
            ),
        }.get(path)
        if content is None:
            self.send_error(404)
            return
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def serve_cdn(self, path):
        match = re.fullmatch(
            r"/tpr/wow/(data|patch|config)/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{32})(\.index)?",
            path,
        )
        if not match or match[2] + match[3] != match[4][:4]:
            self.send_error(404)
            return
        # The active HD config is local and cannot be fetched from stock mirrors.
        if (match[1] == 'config' and not match[5]
                and match[4] == getattr(self.server, 'build_key', None)):
            body = self.server.build_config
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return
        requested_range = self.headers.get("Range")
        if requested_range and not re.fullmatch(
            r"bytes=[0-9]+-[0-9]*", requested_range
        ):
            self.send_error(416)
            return
        ACTIVITY["data_requests"] += 1
        cached = CACHE / path.lstrip("/")
        if cached.is_file() and not requested_range:
            self.send_response(200)
            self.send_header("Content-Length", str(cached.stat().st_size))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            try:
                with cached.open("rb") as stream:
                    shutil.copyfileobj(stream, self.wfile, 64 * 1024)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        headers = {
            "User-Agent": "wrath-classic-local-bridge/1.0",
            "Accept-Encoding": "identity",
        }
        if requested_range:
            headers["Range"] = requested_range
        for mirror in MIRRORS:
            try:
                response = urlopen(Request(mirror + path, headers=headers), timeout=45)
                if requested_range and response.status != 206:
                    response.close()
                    continue
            except Exception:
                continue
            with response:
                self.send_response(response.status)
                for name in (
                    "Content-Length",
                    "Content-Range",
                    "Accept-Ranges",
                    "Content-Type",
                ):
                    if response.headers.get(name):
                        self.send_header(name, response.headers[name])
                self.end_headers()
                try:
                    shutil.copyfileobj(response, self.wfile, 64 * 1024)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            return
        ACTIVITY["data_failures"] += 1
        self.send_error(502, "Pinned CDN object unavailable")

    def log_message(self, *args):
        # Never retain HTTP paths, headers or client data.
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8090), Handler)
    print("Pinned metadata: http://127.0.0.1:8090 (3.4.3.54261)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
