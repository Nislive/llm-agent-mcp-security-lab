# 🔓 Vulnerable-by-Design LLM Agent + MCP Security Lab

A **deliberately vulnerable** local training environment for practicing **manual**
LLM-agent and **MCP (Model Context Protocol)** security testing. You feed an agent
your own payloads through a web UI or CLI — SSRF links, path-traversal paths, SQL
queries, prompt-injection text, XSS payloads — and watch how an agent wired to
unrestrained MCP tools gets abused.

Each of the 5 vulnerabilities ships with a `SAFE_MODE`-gated **defended** variant,
so the exact same payload can be shown **exploitable** vs. **blocked** side by side.

![The lab web UI — chat console, knowledge-base upload, and internal SSRF targets](screenshots/web-ui.png)

> ## ⚠️ SECURITY WARNING
> This project is **intentionally insecure**. Every password, key, and credential
> in it is **FAKE**. Run it only on an **isolated, local** machine. **Do not expose
> it to the internet or any network**, and never point it at real data. It exists
> purely for education.
>
> **Do not open "vulnerability" issues** — the vulnerabilities are the point. See
> [SECURITY.md](SECURITY.md).

---

## The 5 vulnerabilities

| # | Vulnerability | Tool / Component |
|---|---------------|------------------|
| 1 | **SSRF** (internal service + AWS IMDS) | `fetch_web_document` |
| 2 | **Path Traversal** | `read_file` |
| 3 | **SQLi / Confused Deputy** | `run_sql` |
| 4 | **Indirect Prompt Injection → Exfiltration** | `search_kb` + `send_telegram_message` |
| 5 | **Stored XSS** | RAG/DB + unescaped web UI |

Step-by-step manual walkthrough for each → **[MANUAL_TEST_GUIDE.md](MANUAL_TEST_GUIDE.md)**

---

## Demo: indirect prompt injection → exfiltration

An innocent question ("What is Acme's refund policy?") retrieves a **poisoned
knowledge-base document**. The agent treats the hidden instruction inside that
document as a command, silently runs `run_sql` to dump user credentials, and ships
them out via `send_telegram_message` — every step visible in the tool-call log.

![Agent answering a benign question while the tool log shows it running run_sql and exfiltrating credentials over Telegram](screenshots/prompt-injection-exfil.png)

The stolen credentials landing in the attacker's Telegram chat:

![Fake Acme user credentials delivered to a Telegram bot named "Data Exfiltration"](screenshots/telegram-exfiltration.png)

---

## Why this exists

Most vulnerable-app labs (DVWA, WebGoat, Juice Shop) target classic web bugs. This
one targets the **agent trust boundary**: what happens when an LLM can call tools,
and those tools trust the model's arguments, tool output, and retrieved documents
without question. It demonstrates:

- **A confused-deputy agent** — the model abuses its own privileges on the
  attacker's behalf.
- **Indirect prompt injection** — instructions hidden inside a retrieved RAG
  document hijack the agent, with no direct access to the prompt.
- **Attack vs. defense in one repo** — every sink has a paired defended branch, so
  you can flip `SAFE_MODE` and re-run the identical payload to see the mitigation.

Everything runs **fully offline** with no API key (see [Running without an
LLM](#running-without-an-llm-offline-mode)), so the whole thing is reproducible on
a `git clone` with no accounts or network access.

---

## Architecture

```
 Browser ──HTTP──> web_ui.py (Flask :5000) ──import──> agent_client.py (OpenAI / StubPlanner)
    │                  │  /chat        renders agent output UNESCAPED (XSS)                  │
    │                  │  /add_doc     writes an attacker doc straight into ChromaDB         │ stdio (MCP)
    │                  │  /internal-admin        SSRF target (fake internal panel + secrets) ▼
    │                  │  /latest/meta-data/...   fake AWS IMDS (reached via 169.254.169.254) mcp_server.py
    └──────────────────┘                                                            (FastMCP, 5 vulnerable tools)
                                                                                             │
                                         lab.db (users / secrets) + chroma/ (real RAG)  ─────┘
```

- **MCP transport = stdio.** The agent spawns `mcp_server.py` as a subprocess and
  talks MCP over stdin/stdout; every tool call is logged in detail to the terminal.
- **SSRF reachability:** `fetch_web_document` applies no filtering.
  `127.0.0.1:5000/internal-admin` is a real Flask route. `169.254.169.254` is
  transparently rewritten to the local Flask app so the fake IMDS is reachable.

### Components

| File | Role |
|------|------|
| `init_db_and_kb.py` | Builds SQLite (sensitive `users`), `data/secret_config.ini`, the real ChromaDB RAG store, and `.env.example` |
| `mcp_server.py` | FastMCP server; 5 vulnerable tools (each `SAFE_MODE`-gated) |
| `agent_client.py` | LLM agent that connects to MCP + an offline StubPlanner; logs tool calls |
| `web_ui.py` | Flask UI: chat, RAG document upload, `/internal-admin`, fake IMDS |
| `lab_config.py` | Central env access; makes `SAFE_MODE` live-editable |
| `MANUAL_TEST_GUIDE.md` | Step-by-step manual guide for all 5 attacks |

---

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python init_db_and_kb.py
```

> On first run, ChromaDB downloads a small local embedding model (~80 MB, one time).
> After that the lab runs completely offline.

### `.env` settings

`init_db_and_kb.py` generates a `.env.example`, and creates a `.env` from it if one
doesn't exist (it **never** overwrites an existing `.env`). Key variables:

```ini
OPENAI_API_KEY=sk-...        # optional; without it the StubPlanner kicks in
OPENAI_MODEL=gpt-4o-mini
LAB_FORCE_STUB=0             # set to 1 to disable the LLM entirely (offline)
SAFE_MODE=0                  # 0 = VULNERABLE (default), 1 = DEFENDED
TELEGRAM_BOT_TOKEN=          # for real exfil in Step 4 (via @BotFather)
TELEGRAM_CHAT_ID=            # find yours with @userinfobot
LAB_METADATA_BASE=http://127.0.0.1:5000
```

> **Never commit your `.env`.** It is git-ignored by default. The `send_telegram_message`
> tool sends to the real Telegram Bot API when a token is configured; leave the
> token blank and it fails loudly instead (you still see the outbound payload logged).

## Running

```bash
python web_ui.py            # http://127.0.0.1:5000  (tool logs stream in this terminal)
# or, CLI instead of the web UI:
python agent_client.py
```

With the web UI running, open `http://127.0.0.1:5000`, type your payloads into the
"Chat" box, and watch every MCP tool call get logged in the terminal.

---

## SAFE_MODE — attack vs. defense

With `SAFE_MODE=0` (default), every tool is fully exploitable. Set `SAFE_MODE=1`
and each tool loads its **defended** variant instead (SSRF IP blocking, a `data/`
sandbox, read-only SELECT-only SQL, exfil/XSS filters) — the same payloads are now
blocked. Use it to compare attack and defense during a session.

**Changes take effect live:** edit `.env`, save, and refresh the page — no restart.
Flags are read from disk at use-time via `lab_config.py` and passed fresh to each
turn's MCP subprocess. The status bar badge and the UI accent color reflect the
current mode.

## Running without an LLM (offline mode)

With no key set, or `LAB_FORCE_STUB=1`, a deterministic **StubPlanner** runs. It is
deliberately "gullible": it also executes instructions found in tool *output*, so
**Step 4 (indirect injection) works even offline**. For the most realistic behavior,
use a real LLM (an OpenAI key).

## Resetting

After a destructive query (e.g. `DROP TABLE`) or a poisoned RAG store, rebuild
everything:

```bash
python init_db_and_kb.py
```

---

## Disclaimer

This repository is for **authorized security education and research only**. Do not
use it for anything other than learning about these vulnerabilities in your own
isolated environment.
