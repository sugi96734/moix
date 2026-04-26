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
