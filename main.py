from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import ssl
import random
import re
import smtplib
import string
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional

import httpx
import requests
import stripe
from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text,
    create_engine, event, func, text,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from urllib.parse import quote_plus

from dotenv import load_dotenv
load_dotenv()

# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════
logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR   = Path(os.getenv("ARIA_DATA",   "aria_data")); DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_URL     = os.getenv("ARIA_DB_URL")
SECRET_KEY = os.getenv("ARIA_SECRET",   "CHANGE_ME_IN_PRODUCTION_2024")
OLLAMA_URL = os.getenv("OLLAMA_URL",    "http://localhost:11434")
MODEL_NAME = os.getenv("ARIA_MODEL",    "qwen2.5:7b")

SMTP_HOST     = os.getenv("SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER",     "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM",     SMTP_USER)

STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY",     "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_BASIC    = os.getenv("STRIPE_PRICE_BASIC",    "")
STRIPE_PRICE_PREMIUM  = os.getenv("STRIPE_PRICE_PREMIUM",  "")
FRONTEND_URL          = os.getenv("FRONTEND_URL",          "http://localhost:3000")

# ── FIX: Dev mode flag ────────────────────────────────────────
# Set ARIA_DEV_MODE=true in your Render env vars to skip email verification.
# Remove or set to false in production once SMTP is configured.
DEV_MODE = os.getenv("ARIA_DEV_MODE", "false").lower() == "true"

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ── Plan quota definitions ────────────────────────────────────
PLAN_QUOTAS: Dict[str, Dict] = {
    "free": {
        "daily_tokens": 10_000,
        "rpm":          5,
        "rpd":          20,
        "label":        "Free",
        "price_id":     None,
    },
    "basic": {
        "daily_tokens": 100_000,
        "rpm":          20,
        "rpd":          200,
        "label":        "Basic",
        "price_id":     STRIPE_PRICE_BASIC,
    },
    "premium": {
        "daily_tokens": 500_000,
        "rpm":          60,
        "rpd":          1000,
        "label":        "Premium",
        "price_id":     STRIPE_PRICE_PREMIUM,
    },
}

# ══════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════
if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
else:
    DB_URL = f"sqlite:///{DATA_DIR}/aria.db"

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DB_URL else {},
    pool_pre_ping=True,
    echo=False,
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, _):
    if "sqlite" in DB_URL:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id                     = Column(Integer, primary_key=True, index=True)
    username               = Column(String(64),  unique=True, nullable=False, index=True)
    email                  = Column(String(256), unique=True, nullable=False, index=True)
    password               = Column(String(128), nullable=False)
    plan                   = Column(String(32),  nullable=False, default="free")
    stripe_customer_id     = Column(String(128), nullable=True)
    stripe_subscription_id = Column(String(128), nullable=True)
    email_verified         = Column(Boolean, default=False)
    created_at             = Column(DateTime, default=datetime.utcnow)
    last_login             = Column(DateTime, nullable=True)

    reminders     = relationship("Reminder",    back_populates="user", cascade="all, delete-orphan")
    notes         = relationship("Note",        back_populates="user", cascade="all, delete-orphan")
    tasks         = relationship("Task",        back_populates="user", cascade="all, delete-orphan")
    usage_logs    = relationship("UsageLog",    back_populates="user", cascade="all, delete-orphan")
    rate_requests = relationship("RateRequest", back_populates="user", cascade="all, delete-orphan")


class EmailVerification(Base):
    __tablename__ = "email_verifications"
    id         = Column(Integer, primary_key=True)
    email      = Column(String(256), nullable=False, index=True)
    code       = Column(String(6),   nullable=False)
    username   = Column(String(64),  nullable=False)
    password   = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    verified   = Column(Boolean, default=False)


class UsageLog(Base):
    __tablename__  = "usage_logs"
    id             = Column(Integer, primary_key=True)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    date           = Column(String(10), nullable=False, index=True)
    tokens_used    = Column(Integer, default=0)
    requests_count = Column(Integer, default=0)
    user           = relationship("User", back_populates="usage_logs")


class RateRequest(Base):
    __tablename__ = "rate_requests"
    id      = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ts      = Column(DateTime, default=datetime.utcnow, index=True)
    user    = relationship("User", back_populates="rate_requests")


class Reminder(Base):
    __tablename__ = "reminders"
    id            = Column(Integer, primary_key=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    reminder_text = Column(Text,    nullable=False)
    reminder_time = Column(String(32), nullable=False)
    recurrence    = Column(String(16), nullable=True)
    sent          = Column(Boolean, default=False)
    completed     = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    user          = relationship("User", back_populates="reminders")


class Note(Base):
    __tablename__ = "notes"
    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title      = Column(String(256), nullable=False, default="Note")
    content    = Column(Text,        nullable=False, default="")
    color      = Column(String(16),  nullable=False, default="#6C63FF")
    pinned     = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user       = relationship("User", back_populates="notes")


class Task(Base):
    __tablename__ = "tasks"
    id          = Column(Integer, primary_key=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title       = Column(String(256), nullable=False)
    description = Column(Text,        nullable=False, default="")
    completed   = Column(Boolean, default=False)
    priority    = Column(String(16),  nullable=False, default="medium")
    due_date    = Column(String(32),  nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user        = relationship("User", back_populates="tasks")


class WebSearchCache(Base):
    __tablename__ = "web_search_cache"
    id         = Column(Integer, primary_key=True)
    query      = Column(String(512), unique=True, nullable=False, index=True)
    results    = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_sync() -> Session:
    return SessionLocal()


# ══════════════════════════════════════════════════════════════
#  RATE LIMITING & QUOTA
# ══════════════════════════════════════════════════════════════

def check_rate_limit(user: User, db: Session) -> None:
    quota      = PLAN_QUOTAS[user.plan]
    now        = datetime.utcnow()
    today      = now.date().isoformat()
    minute_ago = now - timedelta(minutes=1)

    rpm_count = (
        db.query(func.count(RateRequest.id))
        .filter(RateRequest.user_id == user.id, RateRequest.ts >= minute_ago)
        .scalar()
    )
    if rpm_count >= quota["rpm"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error":   "rate_limit_rpm",
                "message": f"Too many requests. Limit: {quota['rpm']} req/min for {quota['label']} plan.",
                "limit":   quota["rpm"],
                "plan":    user.plan,
                "upgrade": user.plan != "premium",
            },
        )

    log       = db.query(UsageLog).filter_by(user_id=user.id, date=today).first()
    rpd_count = log.requests_count if log else 0
    if rpd_count >= quota["rpd"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error":     "rate_limit_rpd",
                "message":   f"Daily request limit reached ({quota['rpd']} req/day for {quota['label']} plan).",
                "limit":     quota["rpd"],
                "plan":      user.plan,
                "upgrade":   user.plan != "premium",
                "resets_at": (now + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat(),
            },
        )

    db.add(RateRequest(user_id=user.id, ts=now))
    db.query(RateRequest).filter(
        RateRequest.user_id == user.id,
        RateRequest.ts < now - timedelta(days=2),
    ).delete()
    db.commit()


def check_token_quota(user: User, db: Session) -> int:
    quota     = PLAN_QUOTAS[user.plan]
    today     = datetime.utcnow().date().isoformat()
    log       = db.query(UsageLog).filter_by(user_id=user.id, date=today).first()
    used      = log.tokens_used if log else 0
    remaining = quota["daily_tokens"] - used
    if remaining <= 0:
        raise HTTPException(
            status_code=429,
            detail={
                "error":     "quota_exhausted",
                "message":   f"Daily token quota exhausted ({quota['daily_tokens']:,} tokens for {quota['label']} plan).",
                "limit":     quota["daily_tokens"],
                "used":      used,
                "plan":      user.plan,
                "upgrade":   user.plan != "premium",
                "resets_at": (datetime.utcnow() + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat(),
            },
        )
    return remaining


def record_token_usage(user_id: int, tokens: int, db: Session) -> None:
    today = datetime.utcnow().date().isoformat()
    log   = db.query(UsageLog).filter_by(user_id=user_id, date=today).first()
    if log:
        log.tokens_used    += tokens
        log.requests_count += 1
    else:
        db.add(UsageLog(user_id=user_id, date=today, tokens_used=tokens, requests_count=1))
    db.commit()


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def get_usage_stats(user_id: int, db: Session) -> dict:
    today = datetime.utcnow().date().isoformat()
    log   = db.query(UsageLog).filter_by(user_id=user_id, date=today).first()
    used  = log.tokens_used    if log else 0
    reqs  = log.requests_count if log else 0
    user  = db.query(User).filter_by(id=user_id).first()
    quota = PLAN_QUOTAS[user.plan]
    return {
        "plan":             user.plan,
        "daily_tokens":     quota["daily_tokens"],
        "tokens_used":      used,
        "tokens_remaining": max(0, quota["daily_tokens"] - used),
        "requests_today":   reqs,
        "rpm_limit":        quota["rpm"],
        "rpd_limit":        quota["rpd"],
        "resets_at":        (datetime.utcnow() + timedelta(days=1))
                            .replace(hour=0, minute=0, second=0).isoformat(),
    }


# ══════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ══════════════════════════════════════════════════════════════

def _hash_password(password: str) -> str:
    return hmac.new(SECRET_KEY.encode(), password.encode(), hashlib.sha256).hexdigest()

def _make_token(user_id: int, username: str) -> str:
    import base64
    payload = json.dumps({"id": user_id, "u": username, "exp": int(time.time()) + 86400 * 30})
    b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{b64}.{sig}"

def _verify_token(token: str) -> dict:
    import base64
    try:
        b64, sig = token.rsplit(".", 1)
        expected = hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(401, "Invalid token")
        payload = json.loads(base64.urlsafe_b64decode(b64 + "==").decode())
        if payload["exp"] < int(time.time()):
            raise HTTPException(401, "Token expired")
        return payload
    except (ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(401, "Invalid token")

bearer = HTTPBearer()

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db:    Session = Depends(get_db),
) -> User:
    payload = _verify_token(creds.credentials)
    user    = db.query(User).filter_by(id=payload["id"]).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user


# ══════════════════════════════════════════════════════════════
#  EMAIL  ← FIX: correct SMTP protocol selection
# ══════════════════════════════════════════════════════════════

def _generate_code() -> str:
    return "".join(random.choices(string.digits, k=6))


def _send_verification_email(email: str, code: str, username: str) -> bool:
    """
    Sends a verification email.
      - Port 465 → smtplib.SMTP_SSL  (implicit TLS)
      - Port 587 → smtplib.SMTP + STARTTLS  ← was broken before
      - No credentials → logs the code and returns True (dev/test mode)
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning(
            f"📧 SMTP not configured — DEV code for {email}: {code}"
        )
        return True

    html = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px">
      <h1 style="font-size:28px;font-weight:900;color:#6C63FF;letter-spacing:-1px;margin:0">ARIA</h1>
      <p style="color:#8B8FA8;font-size:13px;margin-top:4px">Adaptive Reasoning Intelligence Architecture</p>
      <div style="background:#F8F8FF;border-radius:16px;padding:32px;text-align:center;
                  border:1px solid #E8E8F0;margin-top:24px">
        <p style="color:#2C2C3E;font-size:15px;margin:0 0 20px">
          Hi <strong>{username}</strong>, your code is:
        </p>
        <div style="background:#6C63FF;border-radius:12px;padding:18px 40px;display:inline-block">
          <span style="color:white;font-size:36px;font-weight:900;letter-spacing:10px">{code}</span>
        </div>
        <p style="color:#8B8FA8;font-size:12px;margin:20px 0 0">
          Expires in <strong>10 minutes</strong>.
        </p>
      </div>
    </div>"""

    msg            = MIMEMultipart("alternative")
    msg["From"]    = SMTP_FROM
    msg["To"]      = email
    msg["Subject"] = "🔐 Your ARIA verification code"
    msg.attach(MIMEText(html, "html"))

    try:
        if SMTP_PORT == 465:
            # Implicit SSL — correct for port 465
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=10) as s:
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
        else:
            # STARTTLS — correct for port 587 (and 25)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.ehlo()
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)

        logger.info(f"✅ Verification email sent to {email}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "❌ SMTP auth failed. For Gmail use an App Password "
            "(myaccount.google.com/apppasswords) — NOT your account password."
        )
        return False
    except OSError as e:
        # [Errno 101] Network is unreachable — Render free tier blocks outbound SMTP
        logger.error(
            f"❌ SMTP network error: {e}. "
            "Render blocks outbound SMTP on free plans. "
            "Use SendGrid / Mailgun / Resend via their HTTP API instead, "
            "or set ARIA_DEV_MODE=true to skip email verification."
        )
        return False
    except Exception as e:
        logger.error(f"❌ Email error: {e}")
        return False


def _send_reminder_email(email: str, text_: str, time_: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        return False
    try:
        msg            = MIMEMultipart()
        msg["From"]    = SMTP_FROM
        msg["To"]      = email
        msg["Subject"] = "🔔 ARIA Reminder"
        html = f"<h2>Reminder</h2><p><strong>{text_}</strong></p><p>Scheduled: {time_}</p>"
        msg.attach(MIMEText(html, "html"))
        if SMTP_PORT == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=10) as s:
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.ehlo(); s.starttls(context=ssl.create_default_context()); s.ehlo()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Reminder email error: {e}")
        return False


# ══════════════════════════════════════════════════════════════
#  WEBSOCKET
# ══════════════════════════════════════════════════════════════
active_connections: Dict[int, List[WebSocket]] = defaultdict(list)

async def _ws_send_reminder(user_id: int, text_: str, time_: str) -> bool:
    if user_id not in active_connections or not active_connections[user_id]:
        return False
    msg = {"type": "reminder", "data": {"id": None, "text": text_, "time": time_}}
    for ws in active_connections[user_id]:
        try:
            await ws.send_json(msg)
        except Exception as e:
            logger.error(f"WS send error: {e}")
    return True


# ══════════════════════════════════════════════════════════════
#  MEMORY STORE
# ══════════════════════════════════════════════════════════════
class MemoryStore:
    def __init__(self, user_id: int, username: str):
        d = DATA_DIR / f"user_{user_id}_{username}" / "memory"
        d.mkdir(parents=True, exist_ok=True)
        self.memory_file  = d / "MEMORY.md"
        self.history_file = d / "HISTORY.md"
        self._init()

    def _init(self):
        if not self.memory_file.exists():
            self.memory_file.write_text(
                "# ARIA Long-Term Memory\n\n## User Information\n\n"
                "## Preferences\n\n## Ongoing Tasks\n\n## Important Notes\n\n",
                encoding="utf-8")
        if not self.history_file.exists():
            self.history_file.write_text("# ARIA Conversation History\n\n", encoding="utf-8")

    def read_memory(self)  -> str: return self.memory_file.read_text(encoding="utf-8")
    def write_memory(self, c: str): self.memory_file.write_text(c, encoding="utf-8")

    def patch_memory(self, old: str, new: str) -> bool:
        cur = self.read_memory()
        if old not in cur: return False
        self.write_memory(cur.replace(old, new, 1)); return True

    def append_history(self, user_msg: str, aria_msg: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}]\nUSER: {user_msg}\nARIA: {aria_msg}\n\n---\n\n")

    def read_history(self, last_n: int = 20) -> str:
        text    = self.history_file.read_text(encoding="utf-8")
        entries = text.split("---\n\n")
        return "---\n\n".join(entries[-last_n:]).strip()


# ══════════════════════════════════════════════════════════════
#  WEB SEARCH
# ══════════════════════════════════════════════════════════════
def _search_duckduckgo(query: str, n: int = 3) -> list:
    try:
        url  = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        hdrs = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=hdrs, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        out  = []
        for r in soup.select(".result")[:n]:
            ta = r.select_one(".result__a")
            ts = r.select_one(".result__snippet")
            tu = r.select_one(".result__url")
            if ta and tu:
                link    = tu.get("href", "")
                if link.startswith("/"): link = "https://duckduckgo.com" + link
                snippet = ts.get_text(strip=True) if ts else ""
                content = _fetch_page(link)
                out.append({"title": ta.get_text(strip=True), "link": link,
                             "snippet": snippet, "content": content})
        return out
    except Exception as e:
        logger.error(f"DuckDuckGo error: {e}")
        return []


def _fetch_page(url: str, max_len: int = 500) -> str:
    try:
        r    = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style"]): tag.decompose()
        text = " ".join(soup.get_text(separator=" ", strip=True).split())
        return text[:max_len] + ("..." if len(text) > max_len else "")
    except Exception:
        return ""


def perform_web_search(query: str, db: Session) -> str:
    cutoff = datetime.utcnow() - timedelta(hours=24)
    cached = db.query(WebSearchCache).filter(
        WebSearchCache.query == query,
        WebSearchCache.created_at >= cutoff,
    ).first()
    if cached:
        return cached.results

    results = _search_duckduckgo(query)
    if not results:
        return "No results found."
    fmt = f"Search results for: {query}\n\n"
    for i, r in enumerate(results, 1):
        fmt += f"{i}. {r['title']}\n   URL: {r['link']}\n   {r['snippet']}\n"
        if r["content"]: fmt += f"   Content: {r['content']}\n"
        fmt += "\n"

    entry = db.query(WebSearchCache).filter_by(query=query).first()
    if entry:
        entry.results    = fmt
        entry.created_at = datetime.utcnow()
    else:
        db.add(WebSearchCache(query=query, results=fmt))
    db.commit()
    return fmt


# ══════════════════════════════════════════════════════════════
#  SYSTEM PROMPT & ACTION PARSER
# ══════════════════════════════════════════════════════════════
def build_system_prompt(user: User, mem: MemoryStore) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M (%A)")
    return f"""### ROLE: ARIA
You are ARIA, an advanced AI assistant with persistent memory, reminders, and web search. Created by Evyox (2024).
Current time: {now} | User: {user.username} (Plan: {user.plan})

### LONG-TERM MEMORY
{mem.read_memory()}

### RECENT HISTORY
{mem.read_history(last_n=10)}

### PROTOCOLS
1. Update memory when user shares important info. Use <ARIA_ACTION> at the END of your response.
2. Set reminders with ISO 8601 datetime.
3. Search web for current info with SEARCH_WEB:query
4. NEVER show <ARIA_ACTION> JSON to user.

### ACTION SYNTAX
<ARIA_ACTION>{{"action":"patch_memory","old_text":"...","new_text":"..."}}</ARIA_ACTION>
<ARIA_ACTION>{{"action":"append_note","content":"..."}}</ARIA_ACTION>
<ARIA_ACTION>{{"action":"set_reminder","reminder_text":"...","reminder_time":"ISO8601","recurrence":"daily"}}</ARIA_ACTION>
SEARCH_WEB:your query here"""


def parse_and_apply_action(raw: str, user_id: int, mem: MemoryStore, db: Session) -> tuple[str, bool]:
    for query in re.findall(r"SEARCH_WEB:(.*?)(?:\n|$)", raw, re.IGNORECASE):
        q = query.strip()
        if q:
            results = perform_web_search(q, db)
            raw = raw.replace(f"SEARCH_WEB:{q}", f"[Search: {q}]\n{results}")

    match = re.search(r"<ARIA_ACTION>(.*?)</ARIA_ACTION>", raw, re.DOTALL)
    if not match:
        return raw.strip(), False

    clean = (raw[:match.start()] + raw[match.end():]).strip()
    try:
        data   = json.loads(match.group(1).strip())
        action = data.get("action", "")
        if action == "write_memory":
            mem.write_memory(data.get("content", ""))
        elif action == "patch_memory":
            mem.patch_memory(data.get("old_text", ""), data.get("new_text", ""))
        elif action == "append_note":
            c   = mem.read_memory()
            sec = "## Important Notes\n\n"
            if sec in c:
                mem.write_memory(c.replace(sec, sec + f"- {data['content']}\n", 1))
        elif action == "set_reminder":
            db.add(Reminder(
                user_id=user_id,
                reminder_text=data["reminder_text"],
                reminder_time=data["reminder_time"],
                recurrence=data.get("recurrence"),
            ))
            db.commit()
        return clean, True
    except Exception as e:
        logger.error(f"Action parse error: {e}")
        return clean, False


def check_and_inject_reminders(user_id: int, response: str, db: Session) -> str:
    now  = datetime.now().isoformat()
    rows = db.query(Reminder).filter(
        Reminder.user_id   == user_id,
        Reminder.sent      == False,
        Reminder.completed == False,
        Reminder.reminder_time <= now,
    ).all()
    if not rows: return response
    msgs = []
    for r in rows:
        try: ts = datetime.fromisoformat(r.reminder_time).strftime("%Y-%m-%d %H:%M")
        except: ts = r.reminder_time
        msgs.append(f"🔔 **Reminder ({ts})**: {r.reminder_text}")
        r.sent = True
    db.commit()
    sep = "\n\n---\n\n" if response else ""
    return response + sep + "\n\n".join(msgs)


# ══════════════════════════════════════════════════════════════
#  REMINDER BACKGROUND WORKER
# ══════════════════════════════════════════════════════════════
def _reminder_worker():
    logger.info("Reminder worker started")
    while True:
        try:
            db   = get_db_sync()
            now  = datetime.now().isoformat()
            rows = (
                db.query(Reminder)
                .join(User)
                .filter(Reminder.sent == False, Reminder.completed == False,
                        Reminder.reminder_time <= now)
                .all()
            )
            for r in rows:
                user    = r.user
                sent_ws = False
                if user.id in active_connections:
                    loop = asyncio.get_event_loop()
                    fut  = asyncio.run_coroutine_threadsafe(
                        _ws_send_reminder(user.id, r.reminder_text, r.reminder_time), loop)
                    try:    sent_ws = fut.result(timeout=5)
                    except: pass
                if not sent_ws and user.email:
                    _send_reminder_email(user.email, r.reminder_text, r.reminder_time)
                r.sent = True
                if r.recurrence:
                    try:
                        dt    = datetime.fromisoformat(r.reminder_time)
                        delta = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1),
                                 "monthly": timedelta(days=30)}.get(r.recurrence)
                        if delta:
                            db.add(Reminder(
                                user_id=r.user_id,
                                reminder_text=r.reminder_text,
                                reminder_time=(dt + delta).isoformat(),
                                recurrence=r.recurrence,
                            ))
                    except Exception as e:
                        logger.error(f"Recurrence error: {e}")
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Reminder worker error: {e}")
        time.sleep(60)


threading.Thread(target=_reminder_worker, daemon=True).start()

# ══════════════════════════════════════════════════════════════
#  AI STREAMING  (Groq → Ollama fallback)
# ══════════════════════════════════════════════════════════════
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL",   "llama-3.1-70b-versatile")


async def stream_groq(messages: list, system: str) -> AsyncIterator[str]:
    if not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY not set")
    async with httpx.AsyncClient(timeout=180) as c:
        async with c.stream(
            "POST",
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [{"role": "system", "content": system}] + messages,
                "stream":      True,
                "temperature": 0.1,
                "max_tokens":  4096,
            },
        ) as r:
            if r.status_code != 200:
                body = await r.aread()
                raise ValueError(f"Groq error {r.status_code}: {body.decode()[:200]}")
            async for line in r.aiter_lines():
                if not line.startswith("data: "): continue
                data = line[6:]
                if data == "[DONE]": break
                try:
                    chunk = json.loads(data)
                    token = chunk["choices"][0]["delta"].get("content", "")
                    if token: yield token
                except Exception: continue


async def stream_ollama(messages: list, system: str) -> AsyncIterator[str]:
    payload = {
        "model":    MODEL_NAME,
        "messages": [{"role": "system", "content": system}] + messages,
        "stream":   True,
        "options":  {"temperature": 0.1, "top_p": 0.9},
    }
    async with httpx.AsyncClient(timeout=180) as c:
        async with c.stream("POST", f"{OLLAMA_URL}/api/chat", json=payload) as r:
            async for line in r.aiter_lines():
                if not line.strip(): continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token: yield token
                    if chunk.get("done"): break
                except Exception: continue


async def stream_ai(messages: list, system: str) -> AsyncIterator[str]:
    try:
        async for token in stream_groq(messages, system):
            yield token
    except Exception as e:
        logger.warning(f"Groq failed ({e}), falling back to Ollama")
        async for token in stream_ollama(messages, system):
            yield token


# ══════════════════════════════════════════════════════════════
#  PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════
class RegisterRequest(BaseModel):
    username: str
    email:    str
    password: str

class VerifyEmailRequest(BaseModel):
    email: str
    code:  str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []

class MemoryWriteRequest(BaseModel):
    content: str

class MemoryPatchRequest(BaseModel):
    old_text: str
    new_text: str

class NoteCreateRequest(BaseModel):
    title:   str  = "Note"
    content: str  = ""
    color:   str  = "#6C63FF"
    pinned:  bool = False

class NoteUpdateRequest(BaseModel):
    title:   Optional[str]  = None
    content: Optional[str]  = None
    color:   Optional[str]  = None
    pinned:  Optional[bool] = None

class TaskCreateRequest(BaseModel):
    title:       str
    description: str           = ""
    priority:    str           = "medium"
    due_date:    Optional[str] = None

class TaskUpdateRequest(BaseModel):
    title:       Optional[str]  = None
    description: Optional[str]  = None
    completed:   Optional[bool] = None
    priority:    Optional[str]  = None
    due_date:    Optional[str]  = None

class CheckoutRequest(BaseModel):
    plan: str


# ══════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(title="ARIA API", version="3.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION); return
    try:
        payload = _verify_token(token)
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION); return
    if payload["id"] != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION); return

    await websocket.accept()
    active_connections[user_id].append(websocket)
    logger.info(f"WS connected: user {user_id}")
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections[user_id].remove(websocket)
        if not active_connections[user_id]: del active_connections[user_id]


# ══════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════

@app.post("/auth/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if len(req.username) < 3: raise HTTPException(400, "Username must be ≥ 3 chars")
    if len(req.password) < 6: raise HTTPException(400, "Password must be ≥ 6 chars")
    if "@" not in req.email:  raise HTTPException(400, "Invalid email")

    exists = db.query(User).filter(
        (User.username == req.username.lower()) | (User.email == req.email.lower())
    ).first()
    if exists:
        raise HTTPException(400, "Username or email already exists")

    # ── FIX: Dev mode or no SMTP → skip email, create account immediately ──
    if DEV_MODE or not SMTP_USER or not SMTP_PASSWORD:
        try:
            user = User(
                username=req.username.lower(),
                email=req.email.lower(),
                password=_hash_password(req.password),
                email_verified=True,
            )
            db.add(user); db.flush(); db.commit()
            MemoryStore(user.id, user.username)
            logger.info(
                f"🚀 {'DEV MODE' if DEV_MODE else 'No SMTP'}: "
                f"auto-verified user '{user.username}'"
            )
            token = _make_token(user.id, user.username)
            return {
                "token":    token,
                "username": user.username,
                "plan":     "free",
                "dev_mode": True,
            }
        except Exception:
            db.rollback()
            raise HTTPException(400, "Username or email already exists")

    # ── Production: send verification email ───────────────────
    code    = _generate_code()
    expires = datetime.utcnow() + timedelta(minutes=10)
    db.query(EmailVerification).filter_by(email=req.email.lower()).delete()
    db.add(EmailVerification(
        email=req.email.lower(), code=code,
        username=req.username.lower(), password=_hash_password(req.password),
        expires_at=expires,
    ))
    db.commit()

    sent = _send_verification_email(req.email, code, req.username)
    if not sent:
        # Clean up the pending verification so user can retry
        db.query(EmailVerification).filter_by(email=req.email.lower()).delete()
        db.commit()
        raise HTTPException(503, {
            "error":   "email_unavailable",
            "message": "Could not send verification email. "
                       "Please try again later or contact support.",
        })
    return {"status": "verification_sent", "email": req.email.lower()}


@app.post("/auth/verify-email")
async def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    v = db.query(EmailVerification).filter_by(
        email=req.email.lower(), code=req.code.strip(), verified=False).first()
    if not v:
        raise HTTPException(400, "Invalid or expired code")
    if v.expires_at < datetime.utcnow():
        db.delete(v); db.commit()
        raise HTTPException(400, "Code expired, please register again")

    try:
        user = User(username=v.username, email=v.email, password=v.password,
                    email_verified=True)
        db.add(user); db.flush()
        v.verified = True
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(400, "Username or email already exists")

    MemoryStore(user.id, user.username)
    return {"token": _make_token(user.id, user.username), "username": user.username, "plan": "free"}


@app.post("/auth/resend-code")
async def resend_code(email: str, db: Session = Depends(get_db)):
    v = db.query(EmailVerification).filter_by(email=email.lower(), verified=False).first()
    if not v: raise HTTPException(404, "No pending verification")
    v.code       = _generate_code()
    v.expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    _send_verification_email(email, v.code, v.username)
    return {"status": "code_resent"}


@app.post("/auth/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(
        username=req.username.lower(), password=_hash_password(req.password)).first()
    if not user:
        raise HTTPException(401, "Invalid username or password")
    user.last_login = datetime.utcnow()
    db.commit()
    return {"token": _make_token(user.id, user.username), "username": user.username, "plan": user.plan}


@app.get("/auth/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id":         user.id,
        "username":   user.username,
        "email":      user.email,
        "plan":       user.plan,
        "created_at": user.created_at,
        "last_login": user.last_login,
    }


# ══════════════════════════════════════════════════════════════
#  USAGE STATS
# ══════════════════════════════════════════════════════════════
@app.get("/usage")
async def usage_stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return get_usage_stats(user.id, db)


# ══════════════════════════════════════════════════════════════
#  CHAT (streaming SSE)
# ══════════════════════════════════════════════════════════════
@app.post("/chat")
async def chat(req: ChatRequest, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    if not req.message.strip():
        raise HTTPException(400, "Empty message")

    check_rate_limit(user, db)
    check_token_quota(user, db)

    mem      = MemoryStore(user.id, user.username)
    system   = build_system_prompt(user, mem)
    messages = [{"role": m["role"], "content": m["content"]} for m in req.history[-20:]]
    messages.append({"role": "user", "content": req.message})

    async def generate():
        full_text   = ""
        token_count = 0
        try:
            async for token in stream_ai(messages, system):
                full_text   += token
                token_count += 1
                yield f"data: {json.dumps({'token': token})}\n\n"

            clean, memory_updated = parse_and_apply_action(full_text, user.id, mem, db)
            final = check_and_inject_reminders(user.id, clean, db)
            mem.append_history(req.message, final)

            input_tokens  = estimate_tokens(req.message + system)
            output_tokens = estimate_tokens(full_text)
            record_token_usage(user.id, input_tokens + output_tokens, db)

            yield f"data: {json.dumps({'done': True, 'response': final, 'memory_updated': memory_updated})}\n\n"

        except HTTPException as e:
            yield f"data: {json.dumps({'error': e.detail, 'status': e.status_code})}\n\n"
        except Exception as e:
            logger.error(f"Chat stream error: {e}", exc_info=True)
            yield f"data: {json.dumps({'error': {'message': 'AI service unavailable. Please try again.', 'type': 'ai_error'}})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Access-Control-Allow-Origin": "*"},
    )


# ══════════════════════════════════════════════════════════════
#  STRIPE PAYMENTS
# ══════════════════════════════════════════════════════════════
@app.post("/billing/checkout")
async def create_checkout(req: CheckoutRequest, user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Payments not configured")
    plan = req.plan.lower()
    if plan not in ("basic", "premium"):
        raise HTTPException(400, "Invalid plan")
    price_id = PLAN_QUOTAS[plan]["price_id"]
    if not price_id:
        raise HTTPException(503, f"Price ID for {plan} not configured")

    customer_id = user.stripe_customer_id
    if not customer_id:
        customer    = stripe.Customer.create(email=user.email, name=user.username,
                                              metadata={"user_id": user.id})
        customer_id = customer.id
        user.stripe_customer_id = customer_id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{FRONTEND_URL}/billing/cancel",
        metadata={"user_id": str(user.id), "plan": plan},
    )
    return {"url": session.url, "session_id": session.id}


@app.post("/billing/portal")
async def billing_portal(user: User = Depends(get_current_user)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Payments not configured")
    if not user.stripe_customer_id:
        raise HTTPException(400, "No billing account found")
    session = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=f"{FRONTEND_URL}/profile",
    )
    return {"url": session.url}


@app.post("/billing/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig     = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")
    except Exception as e:
        raise HTTPException(400, str(e))

    etype = event["type"]
    data  = event["data"]["object"]

    if etype == "checkout.session.completed":
        user_id = int(data["metadata"].get("user_id", 0))
        plan    = data["metadata"].get("plan", "free")
        sub_id  = data.get("subscription")
        user    = db.query(User).filter_by(id=user_id).first()
        if user:
            user.plan = plan; user.stripe_subscription_id = sub_id
            db.commit()
            logger.info(f"User {user_id} upgraded to {plan}")

    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub_id = data["id"]
        user   = db.query(User).filter_by(stripe_subscription_id=sub_id).first()
        if user:
            user.plan = "free"; user.stripe_subscription_id = None
            db.commit()

    elif etype == "customer.subscription.updated":
        sub_id   = data["id"]
        user     = db.query(User).filter_by(stripe_subscription_id=sub_id).first()
        if user:
            items    = data.get("items", {}).get("data", [])
            price_id = items[0]["price"]["id"] if items else ""
            for plan_name, pdata in PLAN_QUOTAS.items():
                if pdata.get("price_id") == price_id:
                    user.plan = plan_name; break
            db.commit()

    elif etype == "invoice.payment_failed":
        customer_id = data.get("customer")
        user = db.query(User).filter_by(stripe_customer_id=customer_id).first()
        if user:
            logger.warning(f"Payment failed for user {user.id}")

    return {"status": "ok"}


@app.get("/billing/plans")
async def get_plans():
    return {
        "plans": [
            {
                "id": "free", "label": "Free", "price": 0,
                "daily_tokens": PLAN_QUOTAS["free"]["daily_tokens"],
                "rpm":          PLAN_QUOTAS["free"]["rpm"],
                "rpd":          PLAN_QUOTAS["free"]["rpd"],
                "features":     ["10K tokens/day", "5 req/min", "Basic memory"],
            },
            {
                "id": "basic", "label": "Basic", "price": 9.99,
                "daily_tokens": PLAN_QUOTAS["basic"]["daily_tokens"],
                "rpm":          PLAN_QUOTAS["basic"]["rpm"],
                "rpd":          PLAN_QUOTAS["basic"]["rpd"],
                "features":     ["100K tokens/day", "20 req/min", "Full memory", "Priority support"],
                "price_id":     STRIPE_PRICE_BASIC,
            },
            {
                "id": "premium", "label": "Premium", "price": 24.99,
                "daily_tokens": PLAN_QUOTAS["premium"]["daily_tokens"],
                "rpm":          PLAN_QUOTAS["premium"]["rpm"],
                "rpd":          PLAN_QUOTAS["premium"]["rpd"],
                "features":     ["500K tokens/day", "60 req/min", "Full memory", "Priority AI", "Early access"],
                "price_id":     STRIPE_PRICE_PREMIUM,
            },
        ]
    }


# ══════════════════════════════════════════════════════════════
#  MEMORY ROUTES
# ══════════════════════════════════════════════════════════════
@app.get("/memory")
async def get_memory(user: User = Depends(get_current_user)):
    return {"memory": MemoryStore(user.id, user.username).read_memory()}

@app.put("/memory")
async def write_memory(req: MemoryWriteRequest, user: User = Depends(get_current_user)):
    MemoryStore(user.id, user.username).write_memory(req.content)
    return {"status": "saved"}

@app.patch("/memory")
async def patch_memory(req: MemoryPatchRequest, user: User = Depends(get_current_user)):
    ok = MemoryStore(user.id, user.username).patch_memory(req.old_text, req.new_text)
    if not ok: raise HTTPException(400, "Text not found in memory")
    return {"status": "patched"}

@app.delete("/memory")
async def clear_memory(user: User = Depends(get_current_user)):
    MemoryStore(user.id, user.username).write_memory(
        "# ARIA Long-Term Memory\n\n## User Information\n\n"
        "## Preferences\n\n## Ongoing Tasks\n\n## Important Notes\n\n")
    return {"status": "cleared"}

@app.get("/memory/history")
async def get_history(limit: int = 30, user: User = Depends(get_current_user)):
    return {"history": MemoryStore(user.id, user.username).read_history(last_n=limit)}

@app.delete("/memory/history")
async def clear_history(user: User = Depends(get_current_user)):
    MemoryStore(user.id, user.username).history_file.write_text(
        "# ARIA Conversation History\n\n", encoding="utf-8")
    return {"status": "cleared"}


# ══════════════════════════════════════════════════════════════
#  NOTES
# ══════════════════════════════════════════════════════════════
def _note_dict(n: Note) -> dict:
    return {"id": n.id, "user_id": n.user_id, "title": n.title, "content": n.content,
            "color": n.color, "pinned": n.pinned,
            "created_at": n.created_at.isoformat(), "updated_at": n.updated_at.isoformat()}

@app.get("/notes")
async def get_notes(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notes = db.query(Note).filter_by(user_id=user.id).order_by(
        Note.pinned.desc(), Note.updated_at.desc()).all()
    return {"notes": [_note_dict(n) for n in notes]}

@app.post("/notes")
async def create_note(req: NoteCreateRequest, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    n = Note(user_id=user.id, title=req.title, content=req.content,
             color=req.color, pinned=req.pinned)
    db.add(n); db.commit(); db.refresh(n)
    return _note_dict(n)

@app.put("/notes/{note_id}")
async def update_note(note_id: int, req: NoteUpdateRequest,
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = db.query(Note).filter_by(id=note_id, user_id=user.id).first()
    if not n: raise HTTPException(404, "Note not found")
    for k, v in req.dict(exclude_none=True).items(): setattr(n, k, v)
    n.updated_at = datetime.utcnow()
    db.commit(); db.refresh(n)
    return _note_dict(n)

@app.delete("/notes/{note_id}")
async def delete_note(note_id: int, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    n = db.query(Note).filter_by(id=note_id, user_id=user.id).first()
    if not n: raise HTTPException(404, "Note not found")
    db.delete(n); db.commit()
    return {"status": "deleted"}


# ══════════════════════════════════════════════════════════════
#  TASKS
# ══════════════════════════════════════════════════════════════
def _task_dict(t: Task) -> dict:
    return {"id": t.id, "user_id": t.user_id, "title": t.title,
            "description": t.description, "completed": t.completed,
            "priority": t.priority, "due_date": t.due_date,
            "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat()}

@app.get("/tasks")
async def get_tasks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tasks = db.query(Task).filter_by(user_id=user.id).order_by(
        Task.completed, Task.due_date, Task.created_at.desc()).all()
    return {"tasks": [_task_dict(t) for t in tasks]}

@app.post("/tasks")
async def create_task(req: TaskCreateRequest, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    t = Task(user_id=user.id, title=req.title, description=req.description,
             priority=req.priority, due_date=req.due_date)
    db.add(t); db.commit(); db.refresh(t)
    return _task_dict(t)

@app.put("/tasks/{task_id}")
async def update_task(task_id: int, req: TaskUpdateRequest,
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Task).filter_by(id=task_id, user_id=user.id).first()
    if not t: raise HTTPException(404, "Task not found")
    for k, v in req.dict(exclude_none=True).items(): setattr(t, k, v)
    t.updated_at = datetime.utcnow()
    db.commit(); db.refresh(t)
    return _task_dict(t)

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    t = db.query(Task).filter_by(id=task_id, user_id=user.id).first()
    if not t: raise HTTPException(404, "Task not found")
    db.delete(t); db.commit()
    return {"status": "deleted"}


# ══════════════════════════════════════════════════════════════
#  REMINDERS
# ══════════════════════════════════════════════════════════════
def _rem_dict(r: Reminder) -> dict:
    return {"id": r.id, "user_id": r.user_id, "reminder_text": r.reminder_text,
            "reminder_time": r.reminder_time, "recurrence": r.recurrence,
            "sent": r.sent, "completed": r.completed}

@app.get("/reminders")
async def get_reminders(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Reminder).filter_by(user_id=user.id, completed=False).order_by(
        Reminder.reminder_time).all()
    return {"reminders": [_rem_dict(r) for r in rows]}

@app.post("/reminder/ack/{reminder_id}")
async def ack_reminder(reminder_id: int, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    r = db.query(Reminder).filter_by(id=reminder_id, user_id=user.id).first()
    if not r: raise HTTPException(404, "Reminder not found")
    r.completed = True
    db.commit()
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    ollama_ok   = False
    model_ready = False
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r    = await c.get(f"{OLLAMA_URL}/api/tags")
            tags = r.json().get("models", [])
            ollama_ok   = True
            model_ready = any(MODEL_NAME in m.get("name", "") for m in tags)
    except Exception:
        pass
    return {
        "status":      "ok",
        "aria":        "online",
        "ollama":      "connected" if ollama_ok else "disconnected",
        "model":       MODEL_NAME,
        "model_ready": model_ready,
        "groq":        "configured" if GROQ_API_KEY else "not_configured",
        "stripe":      "configured" if STRIPE_SECRET_KEY else "not_configured",
        "dev_mode":    DEV_MODE,
    }


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
