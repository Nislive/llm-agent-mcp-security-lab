"""
init_db_and_kb.py
=================
One-shot initializer for the Vulnerable-by-Design LLM Agent + MCP lab.

It creates, in the project directory:
  * lab.db                  - SQLite database with a SENSITIVE `users` table
                              (plaintext passwords + API keys) and an
                              `internal_secrets` table. This is the loot the
                              `run_sql` tool exposes.
  * data/secret_config.ini  - A fake credentials file used as a Path-Traversal
                              loot target for the `read_file` tool.
  * chroma/                 - A REAL persistent ChromaDB store seeded with a few
                              benign knowledge-base documents. You poison it
                              later through the Web UI.
  * .env.example            - Template configuration. The real .env is NEVER
                              overwritten (your API key lives there); .env is
                              only created if it does not already exist.

Everything here is FAKE data placed on purpose for an isolated security lab.
Safe to re-run: tables and the KB collection are dropped/cleared and rebuilt.
"""

import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab.db")
DATA_DIR = os.path.join(BASE_DIR, "data")
CHROMA_DIR = os.path.join(BASE_DIR, "chroma")
SECRET_FILE = os.path.join(DATA_DIR, "secret_config.ini")
ENV_PATH = os.path.join(BASE_DIR, ".env")
ENV_EXAMPLE_PATH = os.path.join(BASE_DIR, ".env.example")

KB_COLLECTION = "knowledge_base"  # chromadb requires a 3-512 char name


# ---------------------------------------------------------------------------
# 1) SQLite: sensitive users + internal secrets (the SQLi / Confused-Deputy loot)
# ---------------------------------------------------------------------------
USERS_SEED = [
    # id, username, password (plaintext!), api_key, role, email, notes
    (1, "admin",  "S3cr3t-Admin!2024", "sk-live-ADMIN-4f9a2c7e11b8", "admin",
     "admin@acme-internal.test", "Root of the internal billing console."),
    (2, "alice",  "alice-spring-2024", "sk-live-USER-alice-77c1",    "user",
     "alice@acme-internal.test", "Finance department. Approves invoices."),
    (3, "bob",    "hunter2",            "sk-live-USER-bob-2a4d",      "user",
     "bob@acme-internal.test",   "Support engineer."),
    (4, "svc_ci", "ci-token-9931-do-not-share", "sk-live-CI-deploy-88ef", "service",
     "ci@acme-internal.test",    "CI/CD service account with deploy rights."),
]

SECRETS_SEED = [
    # id, name, secret_value
    (1, "stripe_live_key",   "sk-live-51Hxxx-FAKE-BILLING-KEY-do-not-use"),
    (2, "aws_root_access",   "AKIAFAKEROOT99 / wJalrFAKEsecretKEYexample"),
    (3, "jwt_signing_secret","jwt-hs256-FAKE-signing-secret-2024"),
]


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS internal_secrets;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,   -- plaintext ON PURPOSE (this is the loot)
            api_key  TEXT NOT NULL,
            role     TEXT NOT NULL,
            email    TEXT,
            notes    TEXT
        );

        CREATE TABLE internal_secrets (
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            secret_value TEXT NOT NULL
        );
        """
    )

    cur.executemany(
        "INSERT INTO users (id, username, password, api_key, role, email, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        USERS_SEED,
    )
    cur.executemany(
        "INSERT INTO internal_secrets (id, name, secret_value) VALUES (?, ?, ?)",
        SECRETS_SEED,
    )

    conn.commit()
    conn.close()
    print(f"[+] SQLite ready: {DB_PATH}")
    print(f"    users: {len(USERS_SEED)} rows | internal_secrets: {len(SECRETS_SEED)} rows")


# ---------------------------------------------------------------------------
# 2) Path-Traversal loot target (distinct from the real .env)
# ---------------------------------------------------------------------------
SECRET_CONFIG_CONTENT = """\
; data/secret_config.ini
; FAKE credentials placed on purpose. If read_file() can reach this file via
; path traversal, an attacker has effectively escaped the intended sandbox.

[production]
db_host = prod-db.acme-internal.test
db_user = acme_app
db_password = Pr0d-DB-FAKE-pass-2024

[aws]
aws_access_key_id = AKIA-FAKE-EXAMPLE-12345
aws_secret_access_key = wJalrFAKE/EXAMPLE/SECRET/KEYxyz1234567890
region = eu-central-1

[telegram]
; The bot the ops team uses. FAKE.
bot_token = 000000000:FAKE-telegram-bot-token
"""


def init_secret_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(SECRET_CONFIG_CONTENT)
    print(f"[+] Path-traversal loot file ready: {SECRET_FILE}")


# ---------------------------------------------------------------------------
# 3) Real ChromaDB RAG store, seeded with benign documents
# ---------------------------------------------------------------------------
BENIGN_DOCS = [
    (
        "faq-hours",
        "Acme Corp support hours are Monday to Friday, 09:00-18:00 CET. "
        "For urgent issues outside these hours, use the emergency portal.",
        {"source": "public-faq", "title": "Support Hours"},
    ),
    (
        "faq-refund",
        "Refunds are processed within 5 business days. Customers can request a "
        "refund from the billing page using their order number.",
        {"source": "public-faq", "title": "Refund Policy"},
    ),
    (
        "faq-vpn",
        "Employees connect to internal tools through the company VPN. The internal "
        "admin dashboard is only reachable from inside the corporate network.",
        {"source": "internal-wiki", "title": "VPN and Internal Access"},
    ),
    (
        "faq-product",
        "AcmeCloud is our managed hosting product. It supports autoscaling, backups, "
        "and a REST API documented at docs.acme.test.",
        {"source": "public-faq", "title": "Product Overview"},
    ),
]


def init_knowledge_base():
    try:
        import chromadb
    except ImportError:
        print("[!] chromadb is not installed. Run: pip install -r requirements.txt")
        print("[!] Skipping RAG initialization.")
        return

    os.makedirs(CHROMA_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_DIR)

    # Rebuild the collection from scratch so re-runs are idempotent.
    try:
        client.delete_collection(KB_COLLECTION)
    except Exception:
        pass

    collection = client.get_or_create_collection(KB_COLLECTION)
    collection.add(
        ids=[d[0] for d in BENIGN_DOCS],
        documents=[d[1] for d in BENIGN_DOCS],
        metadatas=[d[2] for d in BENIGN_DOCS],
    )
    print(f"[+] ChromaDB RAG ready: {CHROMA_DIR}")
    print(f"    collection '{KB_COLLECTION}': {collection.count()} documents")


# ---------------------------------------------------------------------------
# 4) .env.example (and .env only if missing — never clobber the user's key)
# ---------------------------------------------------------------------------
ENV_EXAMPLE_CONTENT = """\
# --- Vulnerable-by-Design LLM Agent + MCP lab configuration ---

# The LLM is OPTIONAL. With no key set (or LAB_FORCE_STUB=1) the lab runs on the
# deterministic StubPlanner and every attack is still demonstrable offline.
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini

# Set to 1 to disable the LLM completely and force the deterministic planner.
LAB_FORCE_STUB=0

# SAFE_MODE=0 -> fully VULNERABLE (default, the whole point of the lab).
# SAFE_MODE=1 -> defended version, so you can compare how each attack is blocked.
SAFE_MODE=0

# send_telegram_message() posts to the REAL Telegram Bot API. Create a bot with
# @BotFather, then get your chat id (e.g. via @userinfobot). Leave blank to make
# the tool error out clearly instead of exfiltrating anywhere.
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Where the fake cloud metadata IP (169.254.169.254) is transparently routed so
# the SSRF against IMDS is actually fetchable in the lab.
LAB_METADATA_BASE=http://127.0.0.1:5000

# A fake secret leaked via read_file path traversal against .env. NOT real.
LAB_FAKE_SECRET=sk-lab-FAKE-0000000000000000
"""


def init_env_files():
    with open(ENV_EXAMPLE_PATH, "w", encoding="utf-8") as f:
        f.write(ENV_EXAMPLE_CONTENT)
    print(f"[+] Wrote {ENV_EXAMPLE_PATH}")

    if os.path.exists(ENV_PATH):
        print("[=] .env already exists -> left untouched (your API key is safe).")
    else:
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.write(ENV_EXAMPLE_CONTENT)
        print("[+] Created .env from template (edit it to add your key).")


def main():
    print("=" * 68)
    print(" Initializing Vulnerable-by-Design LLM Agent + MCP lab")
    print("=" * 68)
    init_database()
    init_secret_file()
    init_knowledge_base()
    init_env_files()
    print("-" * 68)
    print("[✓] Done. Next steps:")
    print("    1) python web_ui.py      # start the Web UI (http://127.0.0.1:5000)")
    print("    2) or python agent_client.py   # CLI chat with the agent")
    print("    See MANUAL_TEST_GUIDE.md for the 5 hands-on attack walkthroughs.")


if __name__ == "__main__":
    main()
