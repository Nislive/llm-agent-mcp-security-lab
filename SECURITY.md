# Security Policy

## ⚠️ This project is intentionally vulnerable

This repository is a **deliberately insecure training lab**. Every vulnerability in
it — SSRF, path traversal, SQL injection, indirect prompt injection, exfiltration,
and stored XSS — is present **on purpose**, so people can practice manual LLM-agent
and MCP security testing.

**Please do not open issues or pull requests reporting these vulnerabilities.** They
are the intended, documented behavior of the lab (when `SAFE_MODE=0`). Reports of
"XSS in web_ui.py" or "SQL injection in run_sql" will be closed as by-design.

## All credentials are fake

Every password, API key, token, and secret in this repo is **fabricated** and points
to nothing real. Do not treat any string here as a live credential.

## Safe usage

- Run it only on an **isolated, local** machine.
- **Do not** expose it to the internet or any untrusted network.
- **Do not** point any tool at real data, real services, or a real Telegram bot you
  care about.
- Never put a real secret in `.env` beyond an OpenAI key you're willing to use for
  the lab. `.env` is git-ignored; keep it that way.

## Reporting a *real* problem

If you find an issue that is **not** one of the intended lab vulnerabilities — for
example a packaging bug, a broken `SAFE_MODE=1` defense that should block an attack
but doesn't, or a supply-chain concern — feel free to open a normal issue.
