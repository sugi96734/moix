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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def unix_ts() -> int:
    return int(time.time())


def clamp_int(v: int, lo: int, hi: int) -> int:
    return lo if v < lo else hi if v > hi else v


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_hash(text: str) -> str:
    # Stable "content hash" used for idempotency keys and simple pointers.
    return sha256_hex(text.encode("utf-8"))


HANDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.]{1,22}[a-z0-9])?$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,17}$")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Optional[dict] = None):
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


def http_error(status: int, code: str, message: str, details: Optional[dict] = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"ok": False, "code": code, "message": message, "details": details or {}})


def ensure(condition: bool, status: int, code: str, message: str, details: Optional[dict] = None) -> None:
    if not condition:
        raise http_error(status, code, message, details)


# ============================================================
# Auth: signed token (HMAC-SHA256) with expiry and nonce
# ============================================================


@dataclass(frozen=True)
class TokenClaims:
    uid: str
    exp: int
    nonce: str
    ver: int = 1


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def sign_token(uid: str, ttl_seconds: int = 3600 * 24 * 7) -> str:
    now = unix_ts()
    exp = now + ttl_seconds
    nonce = secrets.token_urlsafe(16)
    payload = {"ver": 1, "uid": uid, "exp": exp, "nonce": nonce}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(AUTH_SECRET, body, hashlib.sha256).digest()
    return _b64u(body) + "." + _b64u(sig)


def verify_token(token: str) -> TokenClaims:
    try:
        body_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise ApiError(401, "auth.bad_token", "Invalid token format")
    try:
        body = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
    except Exception:
        raise ApiError(401, "auth.bad_token", "Invalid token encoding")
    want = hmac.new(AUTH_SECRET, body, hashlib.sha256).digest()
    if not hmac.compare_digest(want, sig):
        raise ApiError(401, "auth.bad_token", "Signature mismatch")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise ApiError(401, "auth.bad_token", "Invalid token payload")

    ver = int(payload.get("ver", 0))
    uid = str(payload.get("uid", ""))
    exp = int(payload.get("exp", 0))
    nonce = str(payload.get("nonce", ""))
    if ver != 1 or not uid or exp <= 0 or not nonce:
        raise ApiError(401, "auth.bad_token", "Malformed token claims")
    if unix_ts() >= exp:
        raise ApiError(401, "auth.expired", "Token expired")
    return TokenClaims(uid=uid, exp=exp, nonce=nonce, ver=ver)


async def get_auth_user(request: Request) -> "UserCtx":
    hdr = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not hdr.startswith("Bearer "):
        raise http_error(401, "auth.missing", "Missing Bearer token")
    token = hdr[len("Bearer ") :].strip()
    try:
        claims = verify_token(token)
    except ApiError as e:
        raise http_error(e.status, e.code, e.message, e.details)
    return UserCtx(uid=claims.uid, token_nonce=claims.nonce, token_exp=claims.exp)


@dataclass(frozen=True)
class UserCtx:
    uid: str
    token_nonce: str
    token_exp: int


# ============================================================
# Pydantic models
# ============================================================


class Ok(BaseModel):
    ok: bool = True


class RegisterIn(BaseModel):
    handle: str = Field(..., min_length=3, max_length=24)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("handle")
    @classmethod
    def _valid_handle(cls, v: str) -> str:
        v = v.strip().lower()
        if not HANDLE_RE.match(v):
            raise ValueError("invalid handle")
        if ".." in v or v.startswith(".") or v.endswith("."):
            raise ValueError("invalid handle")
        return v


class LoginIn(BaseModel):
    handle: str = Field(..., min_length=3, max_length=24)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("handle")
    @classmethod
    def _norm(cls, v: str) -> str:
        v = v.strip().lower()
        if not HANDLE_RE.match(v):
            raise ValueError("invalid handle")
        return v


class AuthOut(BaseModel):
    ok: bool = True
    token: str
    uid: str
    handle: str
    expires_at: int


class ProfilePublic(BaseModel):
    uid: str
    handle: str
    bio: str = ""
    avatar: str = ""
    country: str = ""
    age: int = 0
    prefs: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    updated_at: int = 0


class ProfileMe(ProfilePublic):
    email_hint: str = ""
    settings: Dict[str, Any] = Field(default_factory=dict)


class ProfileUpdateIn(BaseModel):
    bio: Optional[str] = Field(None, max_length=240)
    avatar: Optional[str] = Field(None, max_length=512)
    country: Optional[str] = Field(None, max_length=2)
    age: Optional[int] = Field(None, ge=0, le=120)
    prefs: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    settings: Optional[Dict[str, Any]] = None
    email_hint: Optional[str] = Field(None, max_length=120)

    @field_validator("country")
    @classmethod
    def _country(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().upper()
        if not v:
            return ""
        if len(v) != 2 or not v.isalpha():
            raise ValueError("invalid country")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        if len(v) > 12:
            raise ValueError("too many tags")
        out: List[str] = []
        seen: Set[str] = set()
        for raw in v:
            t = raw.strip().lower()
            if not t:
                continue
            if not TAG_RE.match(t):
                raise ValueError(f"bad tag: {t}")
            if t in seen:
                continue
            seen.add(t)
            out.append(t)
        return out


class BrowseIn(BaseModel):
    limit: int = Field(24, ge=1, le=60)
    seed: Optional[str] = Field(None, max_length=64)
    mode: str = Field("discover", max_length=16)


class BrowseOut(BaseModel):
    ok: bool = True
    mode: str
    seed: str
    results: List[ProfilePublic]


class LikeIn(BaseModel):
    target_uid: str = Field(..., min_length=8, max_length=64)
    like: bool = True


class LikeOut(BaseModel):
    ok: bool = True
    matched: bool = False
    thread_id: Optional[str] = None


class MatchOut(BaseModel):
    ok: bool = True
    matches: List[Dict[str, Any]]


class MessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
    client_msg_id: Optional[str] = Field(None, max_length=80)


class MessageOut(BaseModel):
    ok: bool = True
    message: Dict[str, Any]


class ThreadMessagesOut(BaseModel):
    ok: bool = True
    thread_id: str
    messages: List[Dict[str, Any]]


class BotChatIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
    vibe: str = Field("friendly", max_length=24)
    mode: str = Field("chat", max_length=24)


class BotChatOut(BaseModel):
    ok: bool = True
    reply: str
    meta: Dict[str, Any] = Field(default_factory=dict)
