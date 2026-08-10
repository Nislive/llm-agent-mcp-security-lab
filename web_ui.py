"""
web_ui.py
=========
Flask front-end for the lab. Deliberately insecure in three ways:

  1. It renders the agent's answer and tool output as RAW HTML (no escaping),
     so a <script> payload that reaches the agent executes in your browser
     (Stored / Reflected XSS).
  2. /add_doc drops whatever you submit straight into the ChromaDB knowledge
     base, giving you a channel to plant poisoned documents (indirect prompt
     injection + stored XSS seeding).
  3. It hosts internal-only targets that should never be reachable from a tool:
       * /internal-admin          -> fake internal dashboard leaking secrets
       * /latest/meta-data/...     -> fake AWS IMDSv1 (reached via the
                                      169.254.169.254 SSRF rewrite in the server)

SAFE_MODE is read live from .env on every request (see lab_config), so flipping
it and refreshing the page is enough -- the whole UI recolours to match.

Run:  python web_ui.py   then open  http://127.0.0.1:5000
"""

import os

import lab_config

from flask import Flask, request, redirect, render_template_string, Response
from markupsafe import Markup

import agent_client

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_DIR = os.path.join(BASE_DIR, "chroma")
KB_COLLECTION = "knowledge_base"  # chromadb requires a 3-512 char name

app = Flask(__name__)

# Single-user lab: keep conversation state in module globals.
AGENT_HISTORY = []          # OpenAI-format messages passed back into run_turn
CHAT = []                   # display log: {"role", "content", "tools"}


# ---------------------------------------------------------------------------
# Templates (Jinja). Note the `| safe` filters -> intentional XSS sinks.
# ---------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="en" data-mode="{{ 'safe' if safe_mode else 'vuln' }}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AcmeBot — Vulnerable Agent Lab</title>
  <style>
    :root {
      --bg: #0b0b0e;
      --panel: #121216;
      --sunk: #0e0e12;
      --line: #26262f;
      --hair: #1b1b22;
      --ink: #eae7e0;
      --dim: #9c9992;
      --faint: #6a6862;
      --accent: #ff6a3d;
      --glow: rgba(255,106,61,.15);
      --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, "Cascadia Mono", Consolas, monospace;
      --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
    }
    html[data-mode="safe"] {
      --accent: #5fe3a1;
      --glow: rgba(95,227,161,.13);
    }

    * { box-sizing: border-box; }

    html, body { background: var(--bg); }

    body {
      margin: 0;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* Atmosphere: accent haze at the top over a faint engineering grid. */
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      z-index: 0;
      pointer-events: none;
      background:
        radial-gradient(1100px 400px at 50% -180px, var(--glow), transparent 72%),
        repeating-linear-gradient(0deg, rgba(255,255,255,.014) 0 1px, transparent 1px 36px),
        repeating-linear-gradient(90deg, rgba(255,255,255,.014) 0 1px, transparent 1px 36px);
      transition: background 420ms ease;
    }

    .shell { position: relative; z-index: 1; }

    /* ---------------- header rail ---------------- */
    header.rail {
      position: sticky;
      top: 0;
      z-index: 10;
      border-bottom: 1px solid var(--line);
      background: rgba(11,11,14,.86);
      backdrop-filter: blur(12px);
    }
    .rail-in {
      max-width: 1180px;
      margin: 0 auto;
      padding: 14px 28px;
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    .brand { display: flex; align-items: baseline; gap: 10px; margin-right: auto; }
    .brand b {
      font-size: 15px;
      font-weight: 600;
      letter-spacing: .02em;
    }
    .brand span {
      font-size: 10px;
      letter-spacing: .18em;
      text-transform: uppercase;
      color: var(--faint);
    }
    .brand i {
      display: inline-block;
      width: 9px; height: 9px;
      border-radius: 50%;
      background: var(--accent);
      transform: translateY(-1px);
    }
    html[data-mode="vuln"] .brand i { animation: pulse 2.6s ease-out infinite; }
    @keyframes pulse {
      0%   { box-shadow: 0 0 0 0 var(--glow); }
      70%  { box-shadow: 0 0 0 10px rgba(0,0,0,0); }
      100% { box-shadow: 0 0 0 0 rgba(0,0,0,0); }
    }

    .readout { display: flex; align-items: center; gap: 8px; }
    .readout .k {
      font-size: 10px;
      letter-spacing: .16em;
      text-transform: uppercase;
      color: var(--faint);
    }
    .readout .v { font-size: 12px; color: var(--dim); }
    .chip {
      font-size: 11px;
      letter-spacing: .08em;
      padding: 3px 9px;
      border: 1px solid var(--accent);
      color: var(--accent);
      border-radius: 2px;
      white-space: nowrap;
    }

    /* ---------------- layout ---------------- */
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 30px 28px 90px;
      display: grid;
      grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
      gap: 30px;
      align-items: start;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: minmax(0, 1fr); }
      .rail-in, main { padding-left: 18px; padding-right: 18px; }
    }

    .label {
      font-size: 10px;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--faint);
      margin: 0 0 14px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .label::after {
      content: "";
      flex: 1;
      height: 1px;
      background: var(--hair);
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--hair);
      border-radius: 3px;
      padding: 20px;
    }
    aside { position: sticky; top: 78px; display: grid; gap: 22px; }
    @media (max-width: 900px) { aside { position: static; } }

    /* ---------------- chat ---------------- */
    .empty {
      border: 1px dashed var(--hair);
      border-radius: 3px;
      padding: 30px 22px;
      color: var(--faint);
      font-size: 13px;
      line-height: 1.7;
    }
    .empty code { color: var(--dim); }

    .msg {
      border: 1px solid var(--hair);
      border-left: 2px solid var(--line);
      border-radius: 0 3px 3px 0;
      background: var(--sunk);
      padding: 14px 18px;
      margin-bottom: 14px;
      animation: rise .45s cubic-bezier(.2,.7,.3,1) backwards;
      animation-delay: calc(min(var(--i), 6) * 45ms);
    }
    .msg.bot { border-left-color: var(--accent); }
    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to   { opacity: 1; transform: none; }
    }
    .who {
      font-size: 10px;
      letter-spacing: .18em;
      text-transform: uppercase;
      color: var(--faint);
      margin-bottom: 9px;
    }
    .msg.bot .who { color: var(--accent); }
    .body {
      font-family: var(--serif);
      font-size: 16px;
      line-height: 1.62;
      color: var(--ink);
      overflow-wrap: anywhere;
    }
    .body pre, .body code { font-family: var(--mono); font-size: 13px; }

    details { margin-top: 14px; border-top: 1px solid var(--hair); padding-top: 10px; }
    summary {
      cursor: pointer;
      font-size: 11px;
      letter-spacing: .1em;
      text-transform: uppercase;
      color: var(--faint);
      list-style: none;
      transition: color 140ms ease;
    }
    summary:hover { color: var(--dim); }
    summary::-webkit-details-marker { display: none; }
    summary::before { content: "▸ "; color: var(--accent); }
    details[open] summary::before { content: "▾ "; }
    .call { margin-top: 12px; }
    .call .sig { font-size: 12px; color: var(--dim); overflow-wrap: anywhere; }
    .call .sig b { color: var(--accent); font-weight: 600; }
    pre {
      background: #08080a;
      border: 1px solid var(--hair);
      border-radius: 3px;
      color: #cfccc5;
      padding: 10px 12px;
      margin: 7px 0 0;
      overflow-x: auto;
      font-size: 12px;
      line-height: 1.55;
      max-height: 300px;
    }

    /* ---------------- forms ---------------- */
    textarea, input[type=text] {
      width: 100%;
      background: var(--sunk);
      border: 1px solid var(--line);
      border-radius: 3px;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.55;
      padding: 11px 13px;
      resize: vertical;
      transition: border-color 140ms ease, box-shadow 140ms ease;
    }
    textarea:focus, input[type=text]:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--glow);
    }
    textarea::placeholder, input::placeholder { color: #55534e; }

    .composer { margin-top: 20px; }
    .row { display: flex; gap: 10px; align-items: center; margin-top: 10px; }
    .row .spacer { flex: 1; }

    button {
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: .14em;
      text-transform: uppercase;
      padding: 9px 18px;
      border-radius: 3px;
      border: 1px solid var(--accent);
      background: transparent;
      color: var(--accent);
      cursor: pointer;
      transition: background 150ms ease, color 150ms ease;
    }
    button:hover { background: var(--accent); color: #0b0b0e; }
    button.ghost { border-color: var(--line); color: var(--faint); }
    button.ghost:hover { background: transparent; border-color: var(--dim); color: var(--dim); }

    .hint { font-size: 12px; color: var(--faint); line-height: 1.65; margin: 0 0 14px; }
    .hint code { color: var(--dim); }

    .flash {
      margin: 12px 0 0;
      font-size: 12px;
      color: var(--accent);
      border-left: 2px solid var(--accent);
      padding-left: 10px;
    }

    .targets { display: grid; gap: 9px; }
    .targets a {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      color: var(--dim);
      text-decoration: none;
      font-size: 12px;
      border: 1px solid var(--hair);
      border-radius: 3px;
      padding: 10px 12px;
      transition: border-color 150ms ease, color 150ms ease, transform 150ms ease;
    }
    .targets a:hover { border-color: var(--accent); color: var(--ink); transform: translateX(2px); }
    .targets a em {
      font-style: normal;
      font-size: 10px;
      letter-spacing: .14em;
      text-transform: uppercase;
      color: var(--faint);
    }

    footer {
      max-width: 1180px;
      margin: 0 auto;
      padding: 0 28px 40px;
      font-size: 11px;
      color: var(--faint);
      letter-spacing: .04em;
    }
  </style>
</head>
<body>
<div class="shell">

  <header class="rail">
    <div class="rail-in">
      <div class="brand">
        <i></i>
        <b>AcmeBot</b>
        <span>Vulnerable Agent Lab</span>
      </div>
      <div class="readout">
        <span class="k">Brain</span>
        <span class="v">{{ brain }}</span>
      </div>
      <div class="readout">
        <span class="k">Safe&nbsp;Mode</span>
        <span class="chip">{{ 'ON — DEFENDED' if safe_mode else 'OFF — VULNERABLE' }}</span>
      </div>
    </div>
  </header>

  <main>
    <section>
      <p class="label">Console</p>

      {% if not chat %}
        <div class="empty">
          Send the agent a message or hand it tool syntax directly — for example
          <code>read_file("../.env")</code> or
          <code>fetch_web_document("http://169.254.169.254/latest/meta-data/")</code>.
          Every MCP tool call is logged in detail to the terminal running the server.
        </div>
      {% endif %}

      {% for m in chat %}
        <div class="msg {{ 'bot' if m.role != 'you' else 'you' }}" style="--i: {{ loop.index0 }}">
          <div class="who">{{ m.role }}</div>
          {# INTENTIONAL XSS SINK: agent output rendered as raw HTML #}
          <div class="body">{{ m.content | safe }}</div>
          {% if m.tools %}
          <details>
            <summary>{{ m.tools|length }} tool call(s)</summary>
            {% for t in m.tools %}
              <div class="call">
                <div class="sig"><b>{{ t.name }}</b>({{ t.args | tojson }})</div>
                {# INTENTIONAL XSS SINK: tool result rendered as raw HTML #}
                <pre>{{ t.result | safe }}</pre>
              </div>
            {% endfor %}
          </details>
          {% endif %}
        </div>
      {% endfor %}

      <div class="composer">
        <form method="post" action="/chat">
          <textarea name="message" rows="3" autofocus
                    placeholder="Ask AcmeBot anything... or paste a payload."></textarea>
          <div class="row">
            <button type="submit">Send</button>
            <div class="spacer"></div>
          </div>
        </form>
        <form method="post" action="/reset">
          <button type="submit" class="ghost">Reset chat</button>
        </form>
      </div>
    </section>

    <aside>
      <div class="panel">
        <p class="label">Knowledge Base</p>
        <p class="hint">
          Anything you add here is returned verbatim by <code>search_kb</code>.
          Use it to plant a poisoned instruction or a &lt;script&gt; payload.
        </p>
        <form method="post" action="/add_doc">
          <input type="text" name="doc_id" placeholder="doc id (optional)">
          <div style="height:10px"></div>
          <textarea name="content" rows="7" placeholder="Document text / payload..."></textarea>
          <div class="row">
            <button type="submit">Add to KB</button>
          </div>
        </form>
        {% if kb_message %}<p class="flash">{{ kb_message }}</p>{% endif %}
      </div>

      <div class="panel">
        <p class="label">Internal Targets</p>
        <div class="targets">
          <a href="/internal-admin"><span>/internal-admin</span><em>SSRF</em></a>
          <a href="/latest/meta-data/"><span>/latest/meta-data/</span><em>IMDS</em></a>
        </div>
      </div>
    </aside>
  </main>

  <footer>
    Intentionally insecure · all credentials are fake · for local/isolated training only
  </footer>

</div>
</body>
</html>
"""


def _brain_name():
    return "StubPlanner (offline)" if agent_client._use_stub() else \
        f"OpenAI {lab_config.get('OPENAI_MODEL') or 'gpt-4o-mini'}"


def render_page(kb_message=None):
    return render_template_string(
        PAGE, chat=CHAT, brain=_brain_name(),
        safe_mode=lab_config.safe_mode(), kb_message=kb_message
    )


@app.route("/")
def index():
    return render_page()


@app.route("/chat", methods=["POST"])
def chat():
    global AGENT_HISTORY
    message = request.form.get("message", "").strip()
    if not message:
        return redirect("/")

    CHAT.append({"role": "you", "content": Markup.escape(message), "tools": []})
    out = agent_client.run_turn(message, AGENT_HISTORY)
    AGENT_HISTORY = out["history"]
    # NOTE: content stored raw on purpose (the XSS sink is in the template).
    CHAT.append({"role": "AcmeBot", "content": out["answer"], "tools": out["tool_calls"]})
    return redirect("/")


@app.route("/reset", methods=["POST"])
def reset():
    global AGENT_HISTORY
    AGENT_HISTORY = []
    CHAT.clear()
    return redirect("/")


@app.route("/add_doc", methods=["POST"])
def add_doc():
    content = request.form.get("content", "").strip()
    doc_id = request.form.get("doc_id", "").strip() or f"user-doc-{os.urandom(4).hex()}"
    if not content:
        return render_page(kb_message="Empty document ignored.")
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_DIR)
        collection = client.get_or_create_collection(KB_COLLECTION)
        collection.upsert(ids=[doc_id], documents=[content],
                          metadatas=[{"source": "user-upload"}])
        return render_page(kb_message=f"Added document '{doc_id}' to the knowledge base.")
    except Exception as exc:
        return render_page(kb_message=f"Error: {exc}")


# ---------------------------------------------------------------------------
# SSRF target #1: hidden internal admin dashboard
# ---------------------------------------------------------------------------
@app.route("/internal-admin")
def internal_admin():
    html = """
    <!doctype html><html><head><title>Acme Internal Admin</title></head><body>
    <h1>Acme Corp — Internal Admin Console</h1>
    <p><b>ACCESS LEVEL:</b> internal-network-only. If you are reading this from a
    tool, an SSRF just crossed the trust boundary.</p>
    <h2>Environment</h2>
    <ul>
      <li>INTERNAL_API_KEY = <code>int-admin-FAKE-9f83a1c0e5</code></li>
      <li>DB_DSN = <code>postgres://acme_app:Pr0d-DB-FAKE-pass-2024@prod-db.acme-internal.test/acme</code></li>
      <li>DEPLOY_WEBHOOK = <code>https://deploy.acme-internal.test/hook/FAKE-7712</code></li>
      <li>FEATURE_FLAGS = billing_v2, sso_beta, danger_zone</li>
    </ul>
    <h2>Recent admin actions</h2>
    <table border="1" cellpadding="4">
      <tr><th>user</th><th>action</th></tr>
      <tr><td>admin</td><td>rotated stripe key (FAKE)</td></tr>
      <tr><td>svc_ci</td><td>deployed build #4471</td></tr>
    </table>
    </body></html>
    """
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# SSRF target #2: fake AWS IMDSv1 (reached via the 169.254.169.254 rewrite)
# ---------------------------------------------------------------------------
_FAKE_ROLE = "acme-app-ec2-role"
_FAKE_CREDS = """{
  "Code" : "Success",
  "LastUpdated" : "2026-08-10T09:00:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA-FAKE-EC2ROLE-12345",
  "SecretAccessKey" : "wJalrFAKE/EC2ROLE/SECRET/KEYabc987654321",
  "Token" : "FAKE-SESSION-TOKEN-IMDS-do-not-use",
  "Expiration" : "2026-08-10T15:00:00Z"
}"""


@app.route("/latest/meta-data/")
def imds_root():
    listing = "ami-id\nhostname\ninstance-id\ninstance-type\niam/\nlocal-ipv4\nplacement/\n"
    return Response(listing, mimetype="text/plain")


@app.route("/latest/meta-data/instance-id")
def imds_instance_id():
    return Response("i-0fake1234567890ab", mimetype="text/plain")


@app.route("/latest/meta-data/hostname")
def imds_hostname():
    return Response("ip-10-0-3-14.eu-central-1.compute.internal", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/")
def imds_role_list():
    return Response(_FAKE_ROLE, mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def imds_role_creds(role):
    return Response(_FAKE_CREDS, mimetype="text/plain")


if __name__ == "__main__":
    print("=" * 68)
    print(" Web UI: http://127.0.0.1:5000")
    print(f" brain: {_brain_name()} | SAFE_MODE={lab_config.get('SAFE_MODE', '0')}")
    print(" SAFE_MODE is live: edit .env and refresh the page, no restart needed.")
    print(" Watch THIS terminal for verbose MCP tool-call logs.")
    print("=" * 68)
    # threaded=True so each request can run its own asyncio.run() for the agent.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
