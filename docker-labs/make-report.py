#!/usr/bin/env python3
"""make-report.py — build the static lab report page from results/.

Usage: make-report.py [results-dir] [output-html]
Defaults match the container layout. No external assets: the page is a
single self-contained HTML file (works offline, survives being saved)."""

import html, pathlib, re, sys

RESULTS = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/pqc/results")
OUTFILE = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "/opt/pqc/www/index.html")

LABS = {
    "test-session-reuse":  ("TLS Session Reuse",
        "Proves the documented resumption probe reports false negatives, then demonstrates correct New→Reused testing, session-file key material, fresh key exchange on resumption, and a negative control."),
    "test-revocation":     ("Certificate Revocation (CA side)",
        "Builds a CA, revokes a certificate, and proves the V→R database flip, reason codes in the CRL, verify -crl_check behavior in both directions, CRL signatures, and live OCSP answers."),
    "test-crl-checking":   ("CRL Checking (client side)",
        "The four verification outcomes for one revoked certificate: checking is opt-in, stale CRLs accept revoked certs, fresh CRLs reject (error 23), expired CRLs fail closed (error 12)."),
    "test-ocsp-stapling":  ("OCSP Stapling",
        "No-staple baseline, a stapled good response inside the TLS handshake, and a server delivering signed proof of its own revocation — including the stale-responder trap."),
    "test-renegotiation":  ("TLS Renegotiation",
        "RFC 5746 secure renegotiation on TLS 1.2, a live mid-connection renegotiation (two ClientHellos), and proof that TLS 1.3 removed the mechanism entirely."),
}

TOOLS = [
    ("audit-cnsa2.sh", "CNSA 2.0 compliance audit",
     "Audit any chain file or live endpoint against the CNSA 2.0 profile (ML-DSA-87 / ML-KEM-1024 / SHA-384+). Run inside the container: <code>audit-cnsa2.sh endpoint host:port</code>"),
    ("build-tomcat-stores.sh", "Tomcat/JSSE keystore builder",
     "Builds server + trust stores (PKCS#12 and JKS) for three PQC use cases. JKS conversion of ML-DSA/SLH-DSA stores needs JDK 24+ on the host: <code>build-tomcat-stores.sh ./out</code>"),
]

def read(p, default=""):
    try: return p.read_text(errors="replace")
    except OSError: return default

env = dict(l.split("=", 1) for l in read(RESULTS / "env.txt").splitlines() if "=" in l)

cards, total_pass, total_fail = [], 0, 0
for key, (title, blurb) in LABS.items():
    txt  = read(RESULTS / f"{key}.txt", "(no transcript — lab did not run)")
    meta = dict(l.split("=", 1) for l in read(RESULTS / f"{key}.meta").splitlines() if "=" in l)
    m = re.search(r"PASS=(\d+)\s+FAIL=(\d+)", txt)
    p, f = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    total_pass += p; total_fail += f
    okc  = "ok" if (meta.get("rc") == "0") else "bad"
    badge = f"{p} PASS" + (f" · {f} FAIL" if f else "")
    clean = re.sub(r"\x1b\[[0-9;]*m", "", txt)  # strip ANSI
    cards.append(f"""
    <details class="card {okc}">
      <summary>
        <span class="status {okc}">{badge}</span>
        <span class="title">{html.escape(title)}</span>
        <span class="dur">{html.escape(meta.get('dur','?'))}s</span>
      </summary>
      <p class="blurb">{html.escape(blurb)}</p>
      <pre>{html.escape(clean)}</pre>
    </details>""")

tools_html = "".join(
    f'<div class="tool"><b>{html.escape(t)}</b> — {html.escape(name)}<br><span>{desc}</span></div>'
    for t, name, desc in TOOLS)

verdict = "ALL EXPERIMENTS PASSED" if total_fail == 0 else f"{total_fail} CHECKS FAILED"
vclass  = "ok" if total_fail == 0 else "bad"

OUTFILE.parent.mkdir(parents=True, exist_ok=True)
OUTFILE.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQC for Enterprise IT — Lab Companion</title>
<style>
 :root {{ --bg:#0d1117; --card:#161b22; --line:#30363d; --fg:#e6edf3; --dim:#8b949e;
          --ok:#3fb950; --bad:#f85149; --accent:#79c0ff; }}
 * {{ box-sizing:border-box; }}
 body {{ margin:0; background:var(--bg); color:var(--fg);
        font:16px/1.55 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }}
 .wrap {{ max-width:900px; margin:0 auto; padding:2.5rem 1.25rem 4rem; }}
 header h1 {{ font-size:1.9rem; margin:0 0 .2rem; }}
 header .sub {{ color:var(--dim); margin:0 0 1.4rem; }}
 .verdict {{ display:inline-block; padding:.45rem 1rem; border-radius:8px; font-weight:700;
            letter-spacing:.03em; margin-bottom:1rem; }}
 .verdict.ok  {{ background:rgba(63,185,80,.15);  color:var(--ok);  border:1px solid var(--ok); }}
 .verdict.bad {{ background:rgba(248,81,73,.15); color:var(--bad); border:1px solid var(--bad); }}
 .env {{ color:var(--dim); font-size:.85rem; margin-bottom:2rem; }}
 .env code {{ color:var(--accent); }}
 .intro {{ border-left:3px solid var(--accent); padding:.2rem 0 .2rem 1rem; color:var(--dim);
          margin-bottom:2rem; }}
 .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
         margin-bottom:.9rem; overflow:hidden; }}
 .card summary {{ display:flex; align-items:center; gap:.9rem; padding:.9rem 1.1rem;
                 cursor:pointer; list-style:none; }}
 .card summary::-webkit-details-marker {{ display:none; }}
 .status {{ font-weight:700; font-size:.8rem; padding:.2rem .6rem; border-radius:999px;
           white-space:nowrap; }}
 .status.ok  {{ background:rgba(63,185,80,.15);  color:var(--ok); }}
 .status.bad {{ background:rgba(248,81,73,.15); color:var(--bad); }}
 .title {{ font-weight:600; flex:1; }}
 .dur {{ color:var(--dim); font-size:.85rem; }}
 .blurb {{ color:var(--dim); margin:.2rem 1.1rem .8rem; font-size:.92rem; }}
 pre {{ margin:0; padding:1rem 1.1rem; background:#0a0d12; border-top:1px solid var(--line);
       overflow-x:auto; font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
       color:#c9d1d9; }}
 h2 {{ font-size:1.15rem; margin:2.2rem 0 .8rem; }}
 .tool {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
         padding:.9rem 1.1rem; margin-bottom:.7rem; font-size:.95rem; }}
 .tool span {{ color:var(--dim); font-size:.9rem; }}
 .tool code {{ color:var(--accent); }}
 footer {{ margin-top:3rem; color:var(--dim); font-size:.85rem; border-top:1px solid var(--line);
          padding-top:1.2rem; }}
</style></head><body><div class="wrap">
<header>
  <h1>Post-Quantum Cryptography for Enterprise IT</h1>
  <p class="sub">Lab Companion — the book's experiments, executed on <em>this machine</em>, just now.</p>
  <div class="verdict {vclass}">{verdict} — {total_pass} checks</div>
  <div class="env">Run {html.escape(env.get('date','?'))} · <code>{html.escape(env.get('openssl','?'))}</code>
       · PQC algorithms: <b>{html.escape(env.get('pqc','?'))}</b> · {html.escape(env.get('host',''))}</div>
</header>
<p class="intro">This book keeps one rule: <b>no claim without its experiment</b>. Every transcript
below was produced on your hardware when this container started — not copied from the book.
Expand any card to read the full experiment, including the probes that fail on purpose.</p>
{''.join(cards)}
<h2>Interactive tools in this container</h2>
{tools_html}
<footer>Companion to <i>Post-Quantum Cryptography for Enterprise IT — A Practitioner's Guide</i>.
Lab methodology derives from the MIT-licensed f5devcentral <code>openssl-pqc-stepbystep-lab</code>.
Source and book text: see the repository README.</footer>
</div></body></html>""")
print(f"report: {OUTFILE} ({OUTFILE.stat().st_size} bytes)")
