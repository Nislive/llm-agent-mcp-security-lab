"""
lab_config.py
=============
Live configuration for the lab.

Why this exists: load_dotenv() copies .env into os.environ ONCE, at import time,
and refuses to override anything already present. That made SAFE_MODE feel
flaky -- editing .env and refreshing the page did nothing, because:

  * web_ui.py kept the value it read at startup, so the banner lied; and
  * mcp_server.py is spawned with env=os.environ.copy(), so the subprocess
    inherited the parent's stale value and its own load_dotenv() could not
    override it.

It only ever appeared to work when the key happened to be absent from the
parent's environment at startup, which is why the behaviour looked random.

Here the lab toggles are read back from the .env file at the moment they are
used, so editing .env and refreshing the page is enough -- no restart. Real
shell overrides (`SAFE_MODE=1 python web_ui.py`) still beat the file.

Import this module BEFORE calling load_dotenv() anywhere: it needs a clean view
of the process environment to tell shell overrides apart from .env values.
"""

import os

from dotenv import dotenv_values, load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

# Toggles that must stay live for the whole lab. Everything else can be read
# from os.environ the ordinary way.
LIVE_KEYS = (
    "SAFE_MODE",
    "LAB_FORCE_STUB",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "LAB_METADATA_BASE",
)

# Captured before .env is loaded, so these are genuine shell/CLI overrides and
# always win over the file. In the MCP subprocess this snapshot holds the values
# the parent resolved for that turn (see agent_client._server_params), which is
# exactly what the subprocess should obey.
_SHELL_OVERRIDES = {k: v for k, v in os.environ.items() if k in LIVE_KEYS}

# Still populate os.environ, for third-party libraries that read it directly.
load_dotenv(ENV_PATH)

_cache = {"stamp": None, "values": {}}


def _file_values() -> dict:
    """Re-read .env, memoized on the file's (mtime, size) so edits are picked up."""
    try:
        st = os.stat(ENV_PATH)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    if _cache["stamp"] != stamp:
        _cache["values"] = {
            k: v for k, v in dotenv_values(ENV_PATH).items() if v is not None
        }
        _cache["stamp"] = stamp
    return _cache["values"]


def get(key: str, default: str = "") -> str:
    """Current value of a setting: shell override > live .env > os.environ > default."""
    if key in _SHELL_OVERRIDES:
        return _SHELL_OVERRIDES[key]
    value = _file_values().get(key)
    if value is None:
        value = os.environ.get(key, default)
    return value


def flag(key: str, default: str = "0") -> bool:
    return get(key, default).strip() == "1"


def safe_mode() -> bool:
    """True when the DEFENDED variant of every tool should be used."""
    return flag("SAFE_MODE", "0")


def live_env() -> dict:
    """Freshly resolved lab toggles, to hand down to the MCP subprocess.

    Empty values are included on purpose: they must overwrite whatever stale
    copy the parent is still carrying in os.environ.
    """
    return {key: get(key) for key in LIVE_KEYS}
