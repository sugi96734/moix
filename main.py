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


class ReportIn(BaseModel):
    accused_uid: str = Field(..., min_length=8, max_length=64)
    reason: str = Field(..., min_length=2, max_length=48)
    note: Optional[str] = Field(None, max_length=64)


class ReportOut(BaseModel):
    ok: bool = True
    report_id: int


# ============================================================
# DB schema + helpers
# ============================================================


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    uid TEXT PRIMARY KEY,
    handle TEXT UNIQUE NOT NULL,
    pass_salt TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS profiles (
    uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
    bio TEXT NOT NULL DEFAULT '',
    avatar TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    age INTEGER NOT NULL DEFAULT 0,
    prefs_json TEXT NOT NULL DEFAULT '{}',
    tags_json TEXT NOT NULL DEFAULT '[]',
    settings_json TEXT NOT NULL DEFAULT '{}',
    email_hint TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS edges (
    src_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    dst_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (src_uid, dst_uid, kind)
);

CREATE TABLE IF NOT EXISTS threads (
    thread_id TEXT PRIMARY KEY,
    a_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    b_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_msg_at INTEGER NOT NULL DEFAULT 0,
    meta_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_threads_a ON threads(a_uid);
CREATE INDEX IF NOT EXISTS idx_threads_b ON threads(b_uid);

CREATE TABLE IF NOT EXISTS messages (
    thread_id TEXT NOT NULL REFERENCES threads(thread_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    from_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    text TEXT NOT NULL,
    at INTEGER NOT NULL,
    client_msg_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (thread_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_messages_thread_at ON messages(thread_id, at);

CREATE TABLE IF NOT EXISTS reports (
    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    accused_uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
    uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


def derive_uid(handle: str) -> str:
    # Friendly stable UID: not meant to be secret. Includes a short random suffix to
    # avoid predictability across users with similar handles.
    core = stable_hash(handle)[:16]
    suf = secrets.token_hex(4)
    return f"u_{core}_{suf}"


def password_hash(password: str, salt_b64: str) -> str:
    salt = base64.urlsafe_b64decode((salt_b64 + "===").encode("utf-8"))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000, dklen=32)
    return _b64u(dk)


def new_password_salt() -> str:
    return _b64u(secrets.token_bytes(18))


def deterministic_thread_id(a_uid: str, b_uid: str) -> str:
    x, y = (a_uid, b_uid) if a_uid < b_uid else (b_uid, a_uid)
    raw = f"{x}|{y}|{APP_NAME}|{APP_VERSION}".encode("utf-8")
    return "t_" + sha256_hex(raw)[:40]


def safe_json_loads(s: str, fallback: Any) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return fallback


async def db_connect() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.executescript(SCHEMA)
    await db.commit()
    return db


# ============================================================
# Rate limiting: simple token bucket persisted per user
# ============================================================


class RateLimiter:
    def __init__(self, per_minute: int = 20, burst: int = 40):
        self.per_minute = per_minute
        self.burst = burst

    async def consume(self, db: aiosqlite.Connection, uid: str, cost: int = 1) -> None:
        cost = clamp_int(cost, 1, self.burst)
        now = unix_ts()
        row = await db.execute_fetchone("SELECT bucket, updated_at FROM rate_limits WHERE uid=?", (uid,))
        if row is None:
            bucket = cost
            updated_at = now
            await db.execute("INSERT INTO rate_limits(uid, bucket, updated_at) VALUES(?,?,?)", (uid, bucket, updated_at))
            return
        bucket = int(row["bucket"])
        updated_at = int(row["updated_at"])
        dt = max(0, now - updated_at)
        recover = int((dt * self.per_minute) / 60)
        bucket = max(0, bucket - recover)
        if bucket + cost > self.burst:
            raise http_error(429, "rate.limited", "Slow down")
        bucket += cost
        await db.execute("UPDATE rate_limits SET bucket=?, updated_at=? WHERE uid=?", (bucket, now, uid))


RATE = RateLimiter(per_minute=22, burst=44)


# ============================================================
# Presence / WS hub
# ============================================================


@dataclass
class WsConn:
    uid: str
    thread_id: str
    ws: WebSocket
    connected_at: int
    last_seen_at: int


class WsHub:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._by_thread: Dict[str, Set[WsConn]] = {}

    async def add(self, conn: WsConn) -> None:
        async with self._lock:
            s = self._by_thread.setdefault(conn.thread_id, set())
            s.add(conn)

    async def remove(self, conn: WsConn) -> None:
        async with self._lock:
            s = self._by_thread.get(conn.thread_id)
            if not s:
                return
            s.discard(conn)
            if not s:
                self._by_thread.pop(conn.thread_id, None)

    async def broadcast(self, thread_id: str, payload: dict) -> None:
        async with self._lock:
            conns = list(self._by_thread.get(thread_id, set()))
        if not conns:
            return
        txt = json.dumps(payload, separators=(",", ":"))
        for c in conns:
            try:
                await c.ws.send_text(txt)
            except Exception:
                # best-effort; stale conns are cleaned on disconnect handler
                pass


HUB = WsHub()


# ============================================================
# Friend-finder scoring
# ============================================================


def score_pair(me: ProfilePublic, other: ProfilePublic) -> int:
    s = 1
    if me.country and other.country and me.country == other.country:
        s += 5
    if me.age and other.age:
        diff = abs(me.age - other.age)
        if diff <= 2:
            s += 4
        elif diff <= 5:
            s += 3
        elif diff <= 10:
            s += 2
        elif diff <= 15:
            s += 1
    if me.tags and other.tags:
        overlap = len(set(me.tags).intersection(other.tags))
        s += overlap * 3
    # light prefs overlap: count shared truthy keys at top level
    if me.prefs and other.prefs:
        mkeys = {k for k, v in me.prefs.items() if v}
        okeys = {k for k, v in other.prefs.items() if v}
        s += min(6, len(mkeys.intersection(okeys)))
    # bios that aren't empty add slight confidence
    if other.bio:
        s += 1
    return s


def _shuffle_deterministic(items: List[str], seed: str) -> List[str]:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    # Fisher-Yates with deterministic pseudo RNG based on hash chain
    out = list(items)
    buf = h
    idx = 0
    for i in range(len(out) - 1, 0, -1):
        if idx >= len(buf):
            buf = hashlib.sha256(buf).digest()
            idx = 0
        r = buf[idx]
        idx += 1
        j = r % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out


# ============================================================
# App + lifespan
# ============================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Ensure DB is initialized
    db = await db_connect()
    await db.close()
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors if _cors != [""] else ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        content={"ok": False, "code": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(ValidationError)
async def validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"ok": False, "code": "request.invalid", "message": "Invalid request", "details": exc.errors()},
    )


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    # tiny landing page
    return f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>{APP_NAME}</title>
    <style>
      body{{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;max-width:900px;margin:40px auto;padding:0 16px;}}
      code{{background:#f3f4f6;padding:2px 6px;border-radius:6px;}}
      .box{{border:1px solid #e5e7eb;border-radius:14px;padding:16px;}}
      a{{color:#2563eb;text-decoration:none}}
      a:hover{{text-decoration:underline}}
    </style>
  </head>
  <body>
    <h1>{APP_NAME}</h1>
    <div class="box">
      <p>Backend is running. Open <code>/docs</code> for API docs.</p>
      <p>Website UI expects this backend at <code>http://127.0.0.1:8000</code> by default.</p>
    </div>
  </body>
</html>
""".strip()


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "name": APP_NAME, "version": APP_VERSION, "time": unix_ts()}


# ============================================================
# DB context dependency
# ============================================================


async def get_db() -> aiosqlite.Connection:
    db = await db_connect()
    try:
        yield db
        await db.commit()
    finally:
        await db.close()


# ============================================================
# User + profile helpers
# ============================================================


async def fetch_user_by_handle(db: aiosqlite.Connection, handle: str) -> Optional[aiosqlite.Row]:
    return await db.execute_fetchone("SELECT * FROM users WHERE handle=?", (handle,))


async def fetch_user_by_uid(db: aiosqlite.Connection, uid: str) -> Optional[aiosqlite.Row]:
    return await db.execute_fetchone("SELECT * FROM users WHERE uid=?", (uid,))


async def fetch_profile_row(db: aiosqlite.Connection, uid: str) -> Optional[aiosqlite.Row]:
    return await db.execute_fetchone("SELECT * FROM profiles WHERE uid=?", (uid,))


async def to_public_profile(db: aiosqlite.Connection, uid: str) -> ProfilePublic:
    u = await fetch_user_by_uid(db, uid)
    ensure(u is not None, 404, "user.not_found", "User not found")
    p = await fetch_profile_row(db, uid)
    if p is None:
        # should exist for all users; still handle gracefully
        prefs = {}
        tags = []
        settings = {}
        email_hint = ""
        bio = ""
        avatar = ""
        country = ""
        age = 0
        updated_at = 0
    else:
        prefs = safe_json_loads(p["prefs_json"], {})
        tags = safe_json_loads(p["tags_json"], [])
        settings = safe_json_loads(p["settings_json"], {})
        email_hint = p["email_hint"]
        bio = p["bio"]
        avatar = p["avatar"]
        country = p["country"]
        age = int(p["age"])
        updated_at = int(p["updated_at"])

    return ProfilePublic(
        uid=uid,
        handle=u["handle"],
        bio=bio,
        avatar=avatar,
        country=country,
        age=age,
        prefs=prefs if isinstance(prefs, dict) else {},
        tags=tags if isinstance(tags, list) else [],
        updated_at=updated_at,
    )


async def ensure_not_disabled(urow: aiosqlite.Row) -> None:
    if int(urow["disabled"]) != 0:
        raise http_error(403, "user.disabled", "Account disabled")


# ============================================================
# Auth endpoints
# ============================================================


@app.post("/api/register", response_model=AuthOut)
async def register(body: RegisterIn, db: aiosqlite.Connection = Depends(get_db)) -> AuthOut:
    handle = body.handle.strip().lower()
    ensure(HANDLE_RE.match(handle) is not None, 400, "handle.invalid", "Invalid handle")
    salt = new_password_salt()
    ph = password_hash(body.password, salt)

    exists = await fetch_user_by_handle(db, handle)
    ensure(exists is None, 409, "handle.taken", "Handle already taken")

    uid = derive_uid(handle)
    now = unix_ts()
    await db.execute(
        "INSERT INTO users(uid, handle, pass_salt, pass_hash, created_at, last_login_at) VALUES(?,?,?,?,?,?)",
        (uid, handle, salt, ph, now, now),
    )
    await db.execute(
        "INSERT INTO profiles(uid, bio, avatar, country, age, prefs_json, tags_json, settings_json, email_hint, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uid, "", "", "", 0, "{}", "[]", "{}", "", now),
    )
    token = sign_token(uid)
    claims = verify_token(token)
    return AuthOut(token=token, uid=uid, handle=handle, expires_at=claims.exp)


@app.post("/api/login", response_model=AuthOut)
async def login(body: LoginIn, db: aiosqlite.Connection = Depends(get_db)) -> AuthOut:
    handle = body.handle.strip().lower()
    u = await fetch_user_by_handle(db, handle)
    ensure(u is not None, 404, "auth.not_found", "No such account")
    await ensure_not_disabled(u)
    want = password_hash(body.password, u["pass_salt"])
    ensure(hmac.compare_digest(want, u["pass_hash"]), 401, "auth.bad_password", "Wrong password")
    now = unix_ts()
    await db.execute("UPDATE users SET last_login_at=? WHERE uid=?", (now, u["uid"]))
    token = sign_token(u["uid"])
    claims = verify_token(token)
    return AuthOut(token=token, uid=u["uid"], handle=u["handle"], expires_at=claims.exp)


@app.get("/api/me", response_model=ProfileMe)
async def me(user: UserCtx = Depends(get_auth_user), db: aiosqlite.Connection = Depends(get_db)) -> ProfileMe:
    u = await fetch_user_by_uid(db, user.uid)
    ensure(u is not None, 404, "auth.not_found", "User not found")
    await ensure_not_disabled(u)
    p = await fetch_profile_row(db, user.uid)
    ensure(p is not None, 500, "profile.missing", "Profile missing")
    pub = await to_public_profile(db, user.uid)
    return ProfileMe(
        **pub.model_dump(),
        email_hint=p["email_hint"],
        settings=safe_json_loads(p["settings_json"], {}) if p else {},
    )


@app.put("/api/me", response_model=ProfileMe)
async def update_me(
    body: ProfileUpdateIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> ProfileMe:
    u = await fetch_user_by_uid(db, user.uid)
    ensure(u is not None, 404, "auth.not_found", "User not found")
    await ensure_not_disabled(u)
    p = await fetch_profile_row(db, user.uid)
    ensure(p is not None, 500, "profile.missing", "Profile missing")

    bio = body.bio if body.bio is not None else p["bio"]
    avatar = body.avatar if body.avatar is not None else p["avatar"]
    country = body.country if body.country is not None else p["country"]
    age = body.age if body.age is not None else int(p["age"])
    prefs = body.prefs if body.prefs is not None else safe_json_loads(p["prefs_json"], {})
    tags = body.tags if body.tags is not None else safe_json_loads(p["tags_json"], [])
    settings = body.settings if body.settings is not None else safe_json_loads(p["settings_json"], {})
    email_hint = body.email_hint if body.email_hint is not None else p["email_hint"]

    if not isinstance(prefs, dict):
        prefs = {}
    if not isinstance(tags, list):
        tags = []
    if not isinstance(settings, dict):
        settings = {}
    # compact any large setting values
    if len(json.dumps(settings, ensure_ascii=False)) > 6000:
        raise http_error(400, "settings.too_large", "Settings too large")

    now = unix_ts()
    await RATE.consume(db, user.uid, cost=2)
    await db.execute(
        "UPDATE profiles SET bio=?, avatar=?, country=?, age=?, prefs_json=?, tags_json=?, settings_json=?, email_hint=?, updated_at=? WHERE uid=?",
        (
            bio,
            avatar,
            country,
            int(age),
            json.dumps(prefs, separators=(",", ":"), ensure_ascii=False),
            json.dumps(tags, separators=(",", ":"), ensure_ascii=False),
            json.dumps(settings, separators=(",", ":"), ensure_ascii=False),
            email_hint,
            now,
            user.uid,
        ),
    )
    pub = await to_public_profile(db, user.uid)
    return ProfileMe(**pub.model_dump(), email_hint=email_hint, settings=settings)


# ============================================================
# Browse / likes / matches
# ============================================================


async def set_edge(db: aiosqlite.Connection, src: str, dst: str, kind: str, value: int) -> None:
    now = unix_ts()
    await db.execute(
        "INSERT INTO edges(src_uid, dst_uid, kind, value, updated_at) VALUES(?,?,?,?,?) "
        "ON CONFLICT(src_uid, dst_uid, kind) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (src, dst, kind, int(value), now),
    )


async def get_edge(db: aiosqlite.Connection, src: str, dst: str, kind: str) -> int:
    row = await db.execute_fetchone("SELECT value FROM edges WHERE src_uid=? AND dst_uid=? AND kind=?", (src, dst, kind))
    if row is None:
        return 0
    return int(row["value"])


async def ensure_can_interact(db: aiosqlite.Connection, src: str, dst: str) -> None:
    ensure(src != dst, 400, "edge.self", "Cannot target self")
    ensure(await fetch_user_by_uid(db, dst) is not None, 404, "user.not_found", "Target not found")
    b1 = await get_edge(db, src, dst, "block")
    b2 = await get_edge(db, dst, src, "block")
    ensure(b1 == 0 and b2 == 0, 403, "edge.blocked", "Blocked")


async def ensure_thread(db: aiosqlite.Connection, a_uid: str, b_uid: str) -> str:
    tid = deterministic_thread_id(a_uid, b_uid)
    row = await db.execute_fetchone("SELECT thread_id FROM threads WHERE thread_id=?", (tid,))
    if row is None:
        now = unix_ts()
        x, y = (a_uid, b_uid) if a_uid < b_uid else (b_uid, a_uid)
        await db.execute(
            "INSERT INTO threads(thread_id, a_uid, b_uid, created_at, last_msg_at, meta_json) VALUES(?,?,?,?,?,?)",
            (tid, x, y, now, 0, "{}"),
        )
    return tid


async def is_match(db: aiosqlite.Connection, a_uid: str, b_uid: str) -> bool:
    la = await get_edge(db, a_uid, b_uid, "like")
    lb = await get_edge(db, b_uid, a_uid, "like")
    if la == 1 and lb == 1:
        # ensure neither blocked
        b1 = await get_edge(db, a_uid, b_uid, "block")
        b2 = await get_edge(db, b_uid, a_uid, "block")
        return b1 == 0 and b2 == 0
    return False


@app.post("/api/browse", response_model=BrowseOut)
async def browse(
    body: BrowseIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> BrowseOut:
    await RATE.consume(db, user.uid, cost=1)

    seed = body.seed.strip() if body.seed else ""
    if not seed:
        seed = secrets.token_hex(12)
    mode = (body.mode or "discover").strip().lower()
    limit = clamp_int(body.limit, 1, 60)

    # Collect candidates excluding self and blocked/disabled.
    rows = await db.execute_fetchall("SELECT uid FROM users WHERE disabled=0 AND uid<>?", (user.uid,))
    uids = [r["uid"] for r in rows]

    # Remove blocked in either direction quickly using edges
    # (SQLite is fine for small loads; for large scale you'd add indexes and query joins.)
    blocked_rows = await db.execute_fetchall(
        "SELECT dst_uid FROM edges WHERE src_uid=? AND kind='block' AND value=1",
        (user.uid,),
    )
    blocked_set = {r["dst_uid"] for r in blocked_rows}
    uids = [u for u in uids if u not in blocked_set]

    # deterministic shuffle then score top K window
    uids = _shuffle_deterministic(uids, seed + "|" + mode + "|" + user.uid)
    window = uids[: max(120, limit * 4)]

    me_prof = await to_public_profile(db, user.uid)
    scored: List[Tuple[int, str]] = []
    for uid in window:
        other = await to_public_profile(db, uid)
        if mode == "fresh":
            # prefer recently updated
            s = 1 + int(other.updated_at / 3600) % 50
        elif mode == "quiet":
            # fewer tags, shorter bio; softer vibes
            s = 1 + (10 - min(10, len(other.tags))) + (5 if len(other.bio or "") < 60 else 0)
        else:
            s = score_pair(me_prof, other)
        scored.append((s, uid))

    scored.sort(key=lambda t: (-t[0], t[1]))
    results: List[ProfilePublic] = []
    for s, uid in scored[:limit]:
        results.append(await to_public_profile(db, uid))

    return BrowseOut(mode=mode, seed=seed, results=results)


@app.post("/api/block", response_model=Ok)
async def set_block(
    body: LikeIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> Ok:
    await RATE.consume(db, user.uid, cost=1)
    await ensure_can_interact(db, user.uid, body.target_uid)
    await set_edge(db, user.uid, body.target_uid, "block", 1 if body.like else 0)
    # When blocking, clear likes in both directions for cleanliness
    if body.like:
        await set_edge(db, user.uid, body.target_uid, "like", 0)
        await set_edge(db, body.target_uid, user.uid, "like", 0)
    return Ok()


@app.post("/api/like", response_model=LikeOut)
async def set_like(
    body: LikeIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> LikeOut:
    await RATE.consume(db, user.uid, cost=1)
    await ensure_can_interact(db, user.uid, body.target_uid)

    v = 1 if body.like else 0
    await set_edge(db, user.uid, body.target_uid, "like", v)

    if not body.like:
        return LikeOut(matched=False, thread_id=None)

    matched = await is_match(db, user.uid, body.target_uid)
    if matched:
        tid = await ensure_thread(db, user.uid, body.target_uid)
        return LikeOut(matched=True, thread_id=tid)
    return LikeOut(matched=False, thread_id=None)


@app.get("/api/matches", response_model=MatchOut)
async def matches(
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> MatchOut:
    await RATE.consume(db, user.uid, cost=1)

    # naive approach: scan my likes, then check reciprocal
    rows = await db.execute_fetchall(
        "SELECT dst_uid FROM edges WHERE src_uid=? AND kind='like' AND value=1",
        (user.uid,),
    )
    liked_uids = [r["dst_uid"] for r in rows]
    out: List[Dict[str, Any]] = []
    for dst in liked_uids[:500]:
        if await is_match(db, user.uid, dst):
            tid = deterministic_thread_id(user.uid, dst)
            prof = await to_public_profile(db, dst)
            trow = await db.execute_fetchone("SELECT last_msg_at FROM threads WHERE thread_id=?", (tid,))
            last_msg_at = int(trow["last_msg_at"]) if trow else 0
            out.append({"thread_id": tid, "user": prof.model_dump(), "last_msg_at": last_msg_at})
    out.sort(key=lambda x: (-int(x["last_msg_at"]), x["thread_id"]))
    return MatchOut(matches=out)


# ============================================================
# Threads + messages
# ============================================================


async def ensure_thread_access(db: aiosqlite.Connection, uid: str, thread_id: str) -> aiosqlite.Row:
    t = await db.execute_fetchone("SELECT * FROM threads WHERE thread_id=?", (thread_id,))
    ensure(t is not None, 404, "thread.not_found", "Thread not found")
    ensure(uid in (t["a_uid"], t["b_uid"]), 403, "thread.forbidden", "No access to thread")
    other = t["b_uid"] if uid == t["a_uid"] else t["a_uid"]
    ensure(await is_match(db, uid, other), 403, "thread.not_matched", "Not matched")
    return t


async def next_seq(db: aiosqlite.Connection, thread_id: str) -> int:
    row = await db.execute_fetchone("SELECT MAX(seq) AS m FROM messages WHERE thread_id=?", (thread_id,))
    m = row["m"] if row and row["m"] is not None else 0
    return int(m) + 1


@app.get("/api/threads/{thread_id}/messages", response_model=ThreadMessagesOut)
async def get_messages(
    thread_id: str,
    limit: int = 60,
    before_seq: int = 0,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> ThreadMessagesOut:
    await RATE.consume(db, user.uid, cost=1)
    await ensure_thread_access(db, user.uid, thread_id)
    limit = clamp_int(limit, 1, 200)

    if before_seq <= 0:
        rows = await db.execute_fetchall(
            "SELECT * FROM messages WHERE thread_id=? ORDER BY seq DESC LIMIT ?",
            (thread_id, limit),
        )
    else:
        rows = await db.execute_fetchall(
            "SELECT * FROM messages WHERE thread_id=? AND seq < ? ORDER BY seq DESC LIMIT ?",
            (thread_id, before_seq, limit),
        )
    msgs = []
    for r in reversed(rows):
        msgs.append(
            {
                "thread_id": thread_id,
                "seq": int(r["seq"]),
                "from_uid": r["from_uid"],
                "text": r["text"],
                "at": int(r["at"]),
                "client_msg_id": r["client_msg_id"],
            }
        )
    return ThreadMessagesOut(thread_id=thread_id, messages=msgs)


def _sanitize_message_text(text: str) -> str:
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = t.strip()
    if not t:
        raise http_error(400, "message.empty", "Message empty")
    if len(t) > 2000:
        raise http_error(400, "message.too_long", "Message too long")
    # avoid hidden control characters
    cleaned = []
    for ch in t:
        o = ord(ch)
        if o < 32 and ch not in ("\n", "\t"):
            continue
        cleaned.append(ch)
    return "".join(cleaned)


@app.post("/api/threads/{thread_id}/messages", response_model=MessageOut)
async def post_message(
    thread_id: str,
    body: MessageIn,
    background: BackgroundTasks,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> MessageOut:
    await RATE.consume(db, user.uid, cost=1)
    t = await ensure_thread_access(db, user.uid, thread_id)

    text = _sanitize_message_text(body.text)
    client_msg_id = (body.client_msg_id or "").strip()
    if len(client_msg_id) > 80:
        client_msg_id = client_msg_id[:80]

    # Basic client-id dedupe per thread
    if client_msg_id:
        row = await db.execute_fetchone(
            "SELECT seq FROM messages WHERE thread_id=? AND client_msg_id=? AND from_uid=?",
            (thread_id, client_msg_id, user.uid),
        )
        if row is not None:
            # Return the existing message
            existing_seq = int(row["seq"])
            r = await db.execute_fetchone("SELECT * FROM messages WHERE thread_id=? AND seq=?", (thread_id, existing_seq))
            ensure(r is not None, 500, "message.missing", "Message missing")
            msg = {
                "thread_id": thread_id,
                "seq": int(r["seq"]),
                "from_uid": r["from_uid"],
                "text": r["text"],
                "at": int(r["at"]),
                "client_msg_id": r["client_msg_id"],
            }
            background.add_task(HUB.broadcast, thread_id, {"type": "message", "message": msg, "deduped": True})
            return MessageOut(message=msg)

    seq = await next_seq(db, thread_id)
    at = unix_ts()
    await db.execute(
        "INSERT INTO messages(thread_id, seq, from_uid, text, at, client_msg_id) VALUES(?,?,?,?,?,?)",
        (thread_id, seq, user.uid, text, at, client_msg_id),
    )
    await db.execute("UPDATE threads SET last_msg_at=? WHERE thread_id=?", (at, thread_id))

    msg = {"thread_id": thread_id, "seq": seq, "from_uid": user.uid, "text": text, "at": at, "client_msg_id": client_msg_id}
    background.add_task(HUB.broadcast, thread_id, {"type": "message", "message": msg})

    # Friendly bot nudge in DMs (optional): if message asks, include bot suggestion event.
    if "help me" in text.lower() or "icebreaker" in text.lower():
        other_uid = t["b_uid"] if user.uid == t["a_uid"] else t["a_uid"]
        background.add_task(
            HUB.broadcast,
            thread_id,
            {"type": "hint", "hint": await _bot_icebreaker(db, user.uid, other_uid)},
        )

    return MessageOut(message=msg)


# ============================================================
# WebSocket chat
# ============================================================


async def _ws_auth_uid(ws: WebSocket) -> str:
    token = ws.query_params.get("token", "").strip()
    if not token:
        # allow header too
        hdr = ws.headers.get("authorization") or ws.headers.get("Authorization") or ""
        if hdr.startswith("Bearer "):
            token = hdr[len("Bearer ") :].strip()
    if not token:
        raise ApiError(401, "auth.missing", "Missing token")
    claims = verify_token(token)
    return claims.uid


@app.websocket("/ws/chat/{thread_id}")
async def ws_chat(ws: WebSocket, thread_id: str) -> None:
    await ws.accept()
    conn: Optional[WsConn] = None
    db: Optional[aiosqlite.Connection] = None
    try:
        uid = await _ws_auth_uid(ws)
        db = await db_connect()
        await ensure_thread_access(db, uid, thread_id)

        conn = WsConn(uid=uid, thread_id=thread_id, ws=ws, connected_at=unix_ts(), last_seen_at=unix_ts())
        await HUB.add(conn)
        await ws.send_text(json.dumps({"type": "ready", "thread_id": thread_id, "uid": uid}, separators=(",", ":")))

        while True:
            raw = await ws.receive_text()
            conn.last_seen_at = unix_ts()
            # client can send pings or typing hints
            try:
                obj = json.loads(raw)
            except Exception:
                await ws.send_text(json.dumps({"type": "error", "code": "ws.bad_json"}, separators=(",", ":")))
                continue
            t = str(obj.get("type", "")).strip().lower()
            if t == "ping":
                await ws.send_text(json.dumps({"type": "pong", "t": unix_ts()}, separators=(",", ":")))
            elif t == "typing":
                await HUB.broadcast(thread_id, {"type": "typing", "uid": uid, "at": unix_ts()})
            elif t == "seen":
                await HUB.broadcast(thread_id, {"type": "seen", "uid": uid, "at": unix_ts()})
            else:
                await ws.send_text(json.dumps({"type": "error", "code": "ws.unknown_type"}, separators=(",", ":")))
    except WebSocketDisconnect:
        pass
    except ApiError as e:
        try:
            await ws.send_text(json.dumps({"type": "error", "code": e.code, "message": e.message}, separators=(",", ":")))
        except Exception:
            pass
    except HTTPException as e:
        try:
            await ws.send_text(json.dumps({"type": "error", "code": "http", "message": str(e.detail)}, separators=(",", ":")))
        except Exception:
            pass
    finally:
        if conn is not None:
            await HUB.remove(conn)
        if db is not None:
            await db.close()
        try:
            await ws.close()
        except Exception:
            pass


# ============================================================
# Bot: friendly chat + icebreakers + friend-finder tips
# ============================================================


def _soft_classify(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["match", "matches", "who likes me", "liked me", "swipe", "like back"]):
        return "matching"
    if any(k in t for k in ["profile", "bio", "avatar", "tag", "tags", "settings"]):
        return "profile"
    if any(k in t for k in ["icebreaker", "starter", "first message", "opening line"]):
        return "icebreaker"
    if any(k in t for k in ["report", "block", "harass", "abuse", "spam"]):
        return "safety"
    if any(k in t for k in ["recommend", "discover", "find friends", "people like"]):
        return "discover"
    return "chat"


def _tone(vibe: str) -> str:
    v = (vibe or "").strip().lower()
    if v in {"chill", "calm"}:
        return "chill"
    if v in {"direct", "straight"}:
        return "direct"
    if v in {"funny", "witty"}:
        return "witty"
    return "friendly"


async def _bot_icebreaker(db: aiosqlite.Connection, me_uid: str, other_uid: str) -> str:
    me = await to_public_profile(db, me_uid)
    other = await to_public_profile(db, other_uid)
    shared = sorted(set(me.tags).intersection(other.tags))[:3]
    if shared:
        return f"Try: “Hey! I saw you’re into {', '.join(shared)} — what got you into that?”"
    if other.bio:
        snippet = other.bio.strip().split("\n")[0][:60]
        return f"Try: “Your bio line ‘{snippet}’ caught my eye — tell me more?”"
    return "Try: “What’s something you’ve been obsessed with lately?”"


def _bot_reply(kind: str, vibe: str, text: str) -> Tuple[str, Dict[str, Any]]:
    tone = _tone(vibe)
    meta = {"kind": kind, "tone": tone}
    t = text.strip()

    if kind == "matching":
        if tone == "direct":
            return (
                "Matches happen when you and another person both hit Like. If you want quicker matches: "
                "use 5–8 clear tags, keep your bio specific, and like intentionally (not everyone).",
                meta,
            )
        return (
            "If two people like each other, you’ll see a match and unlock a chat thread. "
            "Quick boost: add a couple of tags that really describe your vibe and ask one specific question in your bio.",
            meta,
        )

    if kind == "profile":
        if tone == "witty":
            return (
                "Think of your profile like a movie trailer: 2–3 specifics, 0 spoilers, and one line that invites a reply. "
                "Tags should be “real you” tags — not “what you think people want.”",
                meta,
            )
        return (
            "Best profiles are easy to respond to: one concrete interest, one preference, and one open question. "
            "Keep tags focused (like 6–10).",
            meta,
        )

    if kind == "icebreaker":
        if tone == "direct":
            return (
                "Use a single question + a reason. Example: “You mentioned hiking — favorite trail and why?” "
                "Avoid one-word openers; they stall.",
                meta,
            )
        if tone == "witty":
            return (
                "Icebreaker recipe: playful constraint + easy answer. Example: “Two snacks for a road trip: what’s your duo?” "
                "Then mirror their answer with a follow-up.",
                meta,
            )
        return (
            "Pick something from their profile and ask a small, answerable question. "
            "If you’re stuck: “What’s a tiny thing that made your week better?”",
            meta,
        )

    if kind == "safety":
        return (
            "If someone’s being weird: block first, then report if needed. You don’t owe anyone a debate. "
            "If you want, paste a short note and I’ll help you phrase a calm boundary message.",
            meta,
        )

    if kind == "discover":
        return (
            "Discovery tip: your tags are your magnet. Add tags that imply stories (e.g., “bouldering”, “afrobeat”, “meal prep”). "
            "Then like people whose tags overlap — it improves conversation quality.",
            meta,
        )

    # default chat
    if tone == "direct":
        return ("Tell me what you’re trying to do: find friends, get more matches, or write a first message — and I’ll be specific.", meta)
    if tone == "witty":
        return ("I’m your tiny wing-bot. Give me a situation and I’ll give you a line that doesn’t sound like a line.", meta)
    return ("I’m here. Want help with your profile, discovery, or messaging someone you matched with?", meta)


@app.post("/api/bot/chat", response_model=BotChatOut)
async def bot_chat(
    body: BotChatIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> BotChatOut:
    await RATE.consume(db, user.uid, cost=1)
    kind = _soft_classify(body.text)
    reply, meta = _bot_reply(kind, body.vibe, body.text)
    # add small personalization
    me = await to_public_profile(db, user.uid)
    if kind in {"chat", "discover"} and me.tags:
        meta["you_tags"] = me.tags[:6]
    return BotChatOut(reply=reply, meta=meta)


# ============================================================
# Reports
# ============================================================


@app.post("/api/report", response_model=ReportOut)
async def report(
    body: ReportIn,
    user: UserCtx = Depends(get_auth_user),
    db: aiosqlite.Connection = Depends(get_db),
) -> ReportOut:
    await RATE.consume(db, user.uid, cost=2)
    ensure(await fetch_user_by_uid(db, body.accused_uid) is not None, 404, "user.not_found", "Accused user not found")
    reason = body.reason.strip().lower()
    note = (body.note or "").strip()
    if len(note) > 64:
        note = note[:64]
    at = unix_ts()
    cur = await db.execute(
        "INSERT INTO reports(reporter_uid, accused_uid, reason, note, at) VALUES(?,?,?,?,?)",
        (user.uid, body.accused_uid, reason, note, at),
    )
    rid = int(cur.lastrowid or 0)
    return ReportOut(report_id=rid)


# ============================================================
