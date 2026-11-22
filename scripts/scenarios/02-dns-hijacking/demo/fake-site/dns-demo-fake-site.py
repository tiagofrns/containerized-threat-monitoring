#!/usr/bin/env python3
"""Serve a labelled demonstration page on the VM's loopback interface."""

from http.server import BaseHTTPRequestHandler, HTTPServer


PAGE = b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FAKE SITE</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #17100d;
      color: #ffddce;
      font-family: system-ui, sans-serif;
      text-align: center;
    }
    h1 {
      margin: 1rem;
      font-size: clamp(3rem, 12vw, 9rem);
      line-height: 1.05;
    }
  </style>
</head>
<body>
  <main><h1>FAKE SITE</h1></main>
</body>
</html>
"""


class DemoPage(BaseHTTPRequestHandler):
    def do_GET(self):
        # Use the same /average path as Analytics for the visual comparison.
        if self.path.split("?", 1)[0] not in ("/", "/average"):
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(PAGE)


if __name__ == "__main__":
    with HTTPServer(("127.0.0.1", 30503), DemoPage) as server:
        print("Demo page: http://127.0.0.1:30503/average", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
