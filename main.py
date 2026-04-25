from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Set, Tuple

import aiosqlite
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

# ============================================================
# moix — friend finder + chatbot backend (single-file app)
# ============================================================

APP_NAME = "moix"
APP_VERSION = "1.0.0"

DB_PATH = os.environ.get("MOIX_DB_PATH") or os.path.join(os.path.dirname(__file__), "moix.sqlite3")

# A fixed secret so the app runs without setup. If you want to rotate it later,
# set MOIX_AUTH_SECRET_B64 to a new base64 key.
_DEFAULT_SECRET_HEX = (
    "9f1a7b3c0d22e8a4c1f0b7d3e6a9c2f1"
    "4d7e0b2c9a1e5f3b8c4d2e9f0a7b1c6d"
    "e3f8a1b0c2d4e6f7a9b8c0d1e2f3a4b5"
)


def _load_secret() -> bytes:
    b64 = os.environ.get("MOIX_AUTH_SECRET_B64")
    if b64:
        try:
            raw = base64.urlsafe_b64decode(b64.encode("utf-8"))
            if len(raw) < 32:
                raise ValueError("secret too short")
            return raw
        except Exception as e:  # pragma: no cover
            raise RuntimeError("Invalid MOIX_AUTH_SECRET_B64") from e
    return bytes.fromhex(_DEFAULT_SECRET_HEX)


AUTH_SECRET = _load_secret()

# Browser UI will likely run on a file:// origin or localhost. Keep permissive for local dev,
# but constrain in production via MOIX_CORS_ORIGINS.
_cors = os.environ.get("MOIX_CORS_ORIGINS", "*").split(",")


