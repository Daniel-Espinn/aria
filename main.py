from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import logging
import smtplib
import threading
import asyncio
import random
import string
import httpx
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Dict, List
from collections import defaultdict

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

#GROQ
from groq_api import call_groq_api, call_groq_stream

#load env
from dotenv import load_dotenv
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ═══════════════════════════ CONFIG ════════════════════════════
OLLAMA_URL  = os.getenv("OLLAMA_URL",  "http://localhost:11434")
MODEL_NAME  = os.getenv("ARIA_MODEL",  "qwen2.5:7b")
DATA_DIR    = Path(os.getenv("ARIA_DATA", "aria_data"))
DB_PATH     = DATA_DIR / "users.db"
SECRET_KEY  = os.getenv("ARIA_SECRET", "CHANGE_ME_IN_PRODUCTION_aria_secret_key_2024")

# Configuración SMTP (opcional)
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)

DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="ARIA API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer()

# ═══════════════════════════ WEBSOCKET CONNECTIONS ══════════════════════
active_connections: Dict[int, List[WebSocket]] = defaultdict(list)

async def send_reminder_websocket(user_id: int, reminder_text: str, reminder_time: str) -> bool:
    """Envía un recordatorio por WebSocket a todas las conexiones activas del usuario."""
    if user_id not in active_connections or not active_connections[user_id]:
        return False
    message = {
        "type": "reminder",
        "data": {
            "id": None,
            "text": reminder_text,
            "time": reminder_time
        }
    }
    for connection in active_connections[user_id]:
        try:
            await connection.send_json(message)
        except Exception as e:
            logger.error(f"Error enviando WebSocket a usuario {user_id}: {e}")
    return True

# ═══════════════════════════ DATABASE ══════════════════════════

INIT_SCRIPT = """
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    UNIQUE NOT NULL,
        email       TEXT    UNIQUE NOT NULL,
        password    TEXT    NOT NULL,
        plan        TEXT    NOT NULL DEFAULT 'free',
        created_at  TEXT    NOT NULL,
        last_login  TEXT
    );
    CREATE TABLE IF NOT EXISTS email_verifications (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        email       TEXT NOT NULL,
        code        TEXT NOT NULL,
        username    TEXT NOT NULL,
        password    TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        verified    INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS reminders (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        reminder_text TEXT NOT NULL,
        reminder_time TEXT NOT NULL,
        recurrence    TEXT,
        sent          INTEGER DEFAULT 0,
        completed     INTEGER DEFAULT 0,
        created_at    TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS web_search_cache (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        query      TEXT UNIQUE NOT NULL,
        results    TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        title      TEXT NOT NULL DEFAULT 'Note',
        content    TEXT NOT NULL DEFAULT '',
        color      TEXT NOT NULL DEFAULT '#6C63FF',
        pinned     INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        title       TEXT NOT NULL,
        description TEXT DEFAULT '',
        completed   INTEGER DEFAULT 0,
        priority    TEXT DEFAULT 'medium',
        due_date    TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
"""

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript(INIT_SCRIPT)
    conn.commit()
    conn.close()

init_db()

# ═══════════════════════════ AUTH ══════════════════════════════

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
            raise HTTPException(status_code=401, detail="Invalid token")
        payload = json.loads(base64.urlsafe_b64decode(b64 + "==").decode())
        if payload["exp"] < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expired")
        return payload
    except (ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    payload = _verify_token(creds.credentials)
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (payload["id"],)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)

# ═══════════════════════════ WEBSOCKET AUTH ══════════════════════
async def get_user_from_token(token: str) -> Optional[int]:
    try:
        payload = _verify_token(token)
        return payload["id"]
    except:
        return None

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    authenticated_user = await get_user_from_token(token)
    if authenticated_user != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    active_connections[user_id].append(websocket)
    logger.info(f"Usuario {user_id} conectado vía WebSocket")

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections[user_id].remove(websocket)
        logger.info(f"Usuario {user_id} desconectado")
        if not active_connections[user_id]:
            del active_connections[user_id]

# ═══════════════════════════ WEB SEARCH FUNCTIONS ══════════════════════

def search_duckduckgo(query: str, num_results: int = 3) -> List[Dict[str, str]]:
    """
    Realiza una búsqueda en DuckDuckGo y devuelve una lista de resultados.
    """
    try:
        # Usar DuckDuckGo HTML (gratuito, sin API key)
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        results = []
        for result in soup.select('.result')[:num_results]:
            title_elem = result.select_one('.result__a')
            snippet_elem = result.select_one('.result__snippet')
            url_elem = result.select_one('.result__url')
            
            if title_elem and url_elem:
                title = title_elem.get_text(strip=True)
                link = url_elem.get('href', '')
                if link.startswith('/'):
                    link = 'https://duckduckgo.com' + link
                snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                
                # Obtener contenido de la página (opcional, puede ralentizar)
                page_content = fetch_webpage_content(link, max_length=500)
                
                results.append({
                    'title': title,
                    'link': link,
                    'snippet': snippet,
                    'content': page_content
                })
        
        return results
    except Exception as e:
        logger.error(f"Error en búsqueda DuckDuckGo: {e}")
        return []

def fetch_webpage_content(url: str, max_length: int = 500) -> str:
    """
    Obtiene el contenido textual de una página web.
    """
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Eliminar scripts y estilos
        for script in soup(['script', 'style']):
            script.decompose()
        
        # Obtener texto
        text = soup.get_text(separator=' ', strip=True)
        # Limpiar espacios múltiples
        text = ' '.join(text.split())
        return text[:max_length] + ('...' if len(text) > max_length else '')
    except Exception as e:
        logger.error(f"Error obteniendo contenido de {url}: {e}")
        return ""

def get_cached_search(query: str, max_age_hours: int = 24) -> Optional[str]:
    """Obtiene resultados de búsqueda cacheados si existen y no han expirado."""
    conn = get_db()
    cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
    row = conn.execute(
        "SELECT results FROM web_search_cache WHERE query = ? AND created_at > ?",
        (query, cutoff)
    ).fetchone()
    conn.close()
    return row['results'] if row else None

def cache_search(query: str, results: str) -> None:
    """Guarda resultados de búsqueda en caché."""
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO web_search_cache (query, results, created_at) VALUES (?, ?, ?)",
        (query, results, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def perform_web_search(query: str) -> str:
    """
    Realiza una búsqueda web y devuelve los resultados formateados como texto.
    """
    # Verificar caché
    cached = get_cached_search(query)
    if cached:
        logger.info(f"Usando caché para búsqueda: {query}")
        return cached

    # Realizar búsqueda
    logger.info(f"Realizando búsqueda web: {query}")
    results = search_duckduckgo(query)
    
    if not results:
        return "No se encontraron resultados para la búsqueda."
    
    # Formatear resultados
    formatted = f"Resultados de búsqueda para: {query}\n\n"
    for i, r in enumerate(results, 1):
        formatted += f"{i}. {r['title']}\n"
        formatted += f"   URL: {r['link']}\n"
        formatted += f"   {r['snippet']}\n"
        if r['content']:
            formatted += f"   Contenido: {r['content']}\n"
        formatted += "\n"
    
    # Guardar en caché
    cache_search(query, formatted)
    
    return formatted

# ═══════════════════════════ EMAIL VERIFICATION HELPERS ══════════════════════

def _generate_code() -> str:
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email: str, code: str, username: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP no configurado, omitiendo verificación de email")
        return True  # En dev sin SMTP, auto-verificar
    try:
        msg = MIMEMultipart('alternative')
        msg["From"]    = SMTP_FROM
        msg["To"]      = email
        msg["Subject"] = "🔐 Tu código de verificación ARIA"

        html = f'''
        <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
          <div style="text-align: center; margin-bottom: 32px;">
            <h1 style="font-size: 28px; font-weight: 900; color: #6C63FF; letter-spacing: -1px; margin: 0;">ARIA</h1>
            <p style="color: #8B8FA8; font-size: 13px; margin-top: 4px;">Adaptive Reasoning Intelligence Architecture</p>
          </div>
          <div style="background: #F8F8FF; border-radius: 16px; padding: 32px; text-align: center; border: 1px solid #E8E8F0;">
            <p style="color: #2C2C3E; font-size: 16px; margin: 0 0 24px;">
              Hola <strong>{username}</strong>, este es tu código de verificación:
            </p>
            <div style="background: #6C63FF; border-radius: 12px; padding: 20px 40px; display: inline-block;">
              <span style="color: white; font-size: 36px; font-weight: 900; letter-spacing: 10px;">{code}</span>
            </div>
            <p style="color: #8B8FA8; font-size: 13px; margin: 24px 0 0;">
              Expira en <strong>10 minutos</strong>. Si no solicitaste esto, ignora este correo.
            </p>
          </div>
          <p style="color: #B0B3C1; font-size: 11px; text-align: center; margin-top: 24px;">
            © 2024 ARIA by Evyox
          </p>
        </div>
        '''
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        logger.info(f"Código de verificación enviado a {email}")
        return True
    except Exception as e:
        logger.error(f"Error enviando verificación a {email}: {e}")
        return False

# ═══════════════════════════ MEMORY ════════════════════════════

class MemoryStore:
    def __init__(self, user_id: int, username: str):
        self.user_dir   = DATA_DIR / f"user_{user_id}_{username}"
        self.memory_dir = self.user_dir / "memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.memory_file  = self.memory_dir / "MEMORY.md"
        self.history_file = self.memory_dir / "HISTORY.md"
        self._init_files()

    def _init_files(self):
        if not self.memory_file.exists():
            self.memory_file.write_text(
                "# ARIA Long-Term Memory\n\n"
                "## User Information\n\n"
                "## Preferences\n\n"
                "## Ongoing Tasks\n\n"
                "## Important Notes\n\n",
                encoding="utf-8",
            )
        if not self.history_file.exists():
            self.history_file.write_text("# ARIA Conversation History\n\n", encoding="utf-8")

    def read_memory(self) -> str:
        return self.memory_file.read_text(encoding="utf-8")

    def write_memory(self, content: str) -> None:
        self.memory_file.write_text(content, encoding="utf-8")

    def patch_memory(self, old_text: str, new_text: str) -> bool:
        current = self.read_memory()
        if old_text not in current:
            return False
        self.write_memory(current.replace(old_text, new_text, 1))
        return True

    def append_history(self, user_msg: str, aria_msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        entry = f"[{ts}]\nUSER: {user_msg}\nARIA: {aria_msg}\n\n---\n\n"
        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(entry)

    def read_history(self, last_n: int = 20) -> str:
        if not self.history_file.exists():
            return ""
        text = self.history_file.read_text(encoding="utf-8")
        entries = text.split("---\n\n")
        recent = entries[-last_n:] if len(entries) > last_n else entries
        return "---\n\n".join(recent).strip()

# ═══════════════════════════ REMINDER FUNCTIONS ══════════════════════

def send_reminder_email(user_email: str, reminder_text: str, reminder_time: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM
        msg["To"] = user_email
        msg["Subject"] = "🔔 Recordatorio de ARIA"

        body = f"""
        <h2>Recordatorio</h2>
        <p><strong>{reminder_text}</strong></p>
        <p>Hora programada: {reminder_time}</p>
        <hr>
        <p>Atentamente,<br>Tu asistente ARIA</p>
        """
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        logger.info(f"Correo enviado a {user_email}: {reminder_text}")
        return True
    except Exception as e:
        logger.error(f"Error enviando correo a {user_email}: {e}")
        return False

def create_reminder(user_id: int, reminder_text: str, reminder_time: str, recurrence: Optional[str] = None) -> None:
    conn = get_db()
    conn.execute(
        """INSERT INTO reminders 
           (user_id, reminder_text, reminder_time, recurrence, created_at) 
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, reminder_text, reminder_time, recurrence, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    logger.info(f"Recordatorio guardado para usuario {user_id}: {reminder_text} a las {reminder_time} (recurrencia: {recurrence})")

def get_pending_reminders(user_id: int) -> list[dict]:
    conn = get_db()
    now = datetime.now().isoformat()
    rows = conn.execute(
        """SELECT id, reminder_text, reminder_time, recurrence 
           FROM reminders 
           WHERE user_id = ? AND sent = 0 AND completed = 0 AND reminder_time <= ?""",
        (user_id, now)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def mark_reminder_sent(reminder_id: int) -> None:
    conn = get_db()
    conn.execute("UPDATE reminders SET sent = 1 WHERE id = ?", (reminder_id,))
    conn.commit()
    conn.close()

def complete_reminder(reminder_id: int) -> None:
    """Marca un recordatorio como completado y genera el siguiente si es recurrente."""
    conn = get_db()
    row = conn.execute("SELECT user_id, reminder_text, reminder_time, recurrence FROM reminders WHERE id = ?", (reminder_id,)).fetchone()
    if not row:
        conn.close()
        return
    user_id = row["user_id"]
    text = row["reminder_text"]
    time_str = row["reminder_time"]
    recurrence = row["recurrence"]

    conn.execute("UPDATE reminders SET completed = 1 WHERE id = ?", (reminder_id,))
    conn.commit()

    if recurrence:
        try:
            current_time = datetime.fromisoformat(time_str)
            if recurrence == "daily":
                next_time = current_time + timedelta(days=1)
            elif recurrence == "weekly":
                next_time = current_time + timedelta(weeks=1)
            elif recurrence == "monthly":
                next_time = current_time + timedelta(days=30)
            else:
                next_time = None
            if next_time:
                next_time_str = next_time.isoformat()
                conn.execute(
                    """INSERT INTO reminders (user_id, reminder_text, reminder_time, recurrence, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (user_id, text, next_time_str, recurrence, datetime.now().isoformat())
                )
                conn.commit()
                logger.info(f"Nuevo recordatorio recurrente creado para usuario {user_id}: {text} a las {next_time_str}")
        except Exception as e:
            logger.error(f"Error creando siguiente recordatorio recurrente: {e}")
    conn.close()

def check_and_send_reminders_background():
    """
    Worker que cada 60 segundos revisa recordatorios pendientes.
    """
    logger.info("Worker de recordatorios iniciado")
    while True:
        try:
            conn = get_db()
            rows = conn.execute(
                """SELECT r.id, r.reminder_text, r.reminder_time, 
                          u.id as user_id, u.email 
                   FROM reminders r 
                   JOIN users u ON r.user_id = u.id 
                   WHERE r.sent = 0 AND r.completed = 0 AND r.reminder_time <= ?""",
                (datetime.now().isoformat(),)
            ).fetchall()
            conn.close()

            for row in rows:
                reminder_id = row["id"]
                user_id = row["user_id"]
                email = row["email"]
                text = row["reminder_text"]
                time_str = row["reminder_time"]

                # Intentar WebSocket
                sent_ws = False
                if user_id in active_connections and active_connections[user_id]:
                    loop = asyncio.get_event_loop()
                    future = asyncio.run_coroutine_threadsafe(
                        send_reminder_websocket(user_id, text, time_str),
                        loop
                    )
                    try:
                        sent_ws = future.result(timeout=5)
                    except Exception as e:
                        logger.error(f"Error enviando WebSocket a usuario {user_id}: {e}")

                if sent_ws:
                    mark_reminder_sent(reminder_id)
                    logger.info(f"Recordatorio {reminder_id} enviado por WebSocket a usuario {user_id}")
                    continue

                if email:
                    sent_email = send_reminder_email(email, text, time_str)
                    if sent_email:
                        mark_reminder_sent(reminder_id)
                        continue

                logger.info(f"Recordatorio {reminder_id} pendiente (usuario {user_id} no conectado, sin correo)")

        except Exception as e:
            logger.error(f"Error en worker de recordatorios: {e}")

        time.sleep(60)

def check_and_send_reminders_in_chat(user_id: int, current_response: str) -> str:
    """
    Busca recordatorios pendientes y los agrega a la respuesta del chat.
    """
    pending = get_pending_reminders(user_id)
    if not pending:
        return current_response

    reminder_messages = []
    for rem in pending:
        try:
            dt = datetime.fromisoformat(rem["reminder_time"])
            time_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            time_str = rem["reminder_time"]
        reminder_messages.append(
            f"🔔 **Recordatorio ({time_str})**: {rem['reminder_text']}\n\n"
            f"_[Confirma que lo has leído haciendo clic aquí](javascript:confirmReminder({rem['id']}))_"
        )
        mark_reminder_sent(rem["id"])

    if reminder_messages:
        separator = "\n\n---\n\n" if current_response else ""
        return current_response + separator + "\n\n".join(reminder_messages)
    return current_response

# Iniciar worker
threading.Thread(target=check_and_send_reminders_background, daemon=True).start()

# ═══════════════════════════ SYSTEM PROMPT ══════════════════════

def build_system_prompt(user: dict, mem: MemoryStore) -> str:
    now = datetime.now()
    current_time_str = now.strftime("%Y-%m-%d %H:%M (%A) %Z")
    memory_md = mem.read_memory()
    recent_history = mem.read_history(last_n=10)

    return f"""### ROLE: ARIA
You are ARIA, an advanced AI Assistant with persistent cognitive architecture. Created by Evyox (2024).
Your goal is to assist the user while evolving your knowledge base through active memory management.

### CONTEXT
- **Current Time:** {current_time_str}
- **User:** {user['username']} (Plan: {user['plan']})

### 🧠 LONG-TERM MEMORY (MEMORY.md)
This is your current knowledge about the user. Read it carefully before responding:
---
{memory_md}
---

### 💬 RECENT CONVERSATION HISTORY
{recent_history}

### 🛠 MANDATORY OPERATIONAL PROTOCOLS

1. **MEMORY EVOLUTION (CRITICAL):** If the user provides new info (name, age, job, preferences, goals) or you complete a task, you **MUST** update MEMORY.md. 
   - Use `patch_memory` to update specific lines (best for names/preferences).
   - Use `append_note` for general facts.
   - **Format:** The JSON block must be the ABSOLUTE LAST thing in your message. No text after it.

2. **REASONING BEFORE ACTION:**
   Internalize: "Does this message contain info worth remembering?" If yes, prepare the `<ARIA_ACTION>` block.

3. **ACTION SYNTAX:**
   - **patch_memory:** Requires `old_text` (exact match) and `new_text`.
   - **append_note:** Requires `content`.
   - **set_reminder:** Requires `reminder_text` and `reminder_time` (ISO 8601).

4. **FORBIDDEN:** - Do NOT show the JSON block to the user. 
   - Do NOT use Markdown code blocks (```json) inside `<ARIA_ACTION>`. Use raw JSON.

### ACTION EXAMPLES (FOR INTERNAL USE)

- **User says:** "I am a Flutter developer."
  **Response:** "That's great! I've updated your profile."
  <ARIA_ACTION>{{"action": "patch_memory", "old_text": "## User Information\\n\\n", "new_text": "## User Information\\n- Role: Flutter Developer\\n"}}</ARIA_ACTION>

- **User says:** "Remember that I like dark coffee."
  **Response:** "Noted. I'll remember that."
  <ARIA_ACTION>{{"action": "append_note", "content": "User prefers dark coffee"}}</ARIA_ACTION>

- **User says:** "Search for NVIDIA stock price."
  **Response:** "Searching... SEARCH_WEB:NVIDIA stock price"

### 🚀 COMMAND RECAP
- Memory: `<ARIA_ACTION>{{"action": "...", ...}}</ARIA_ACTION>`
- Search: `SEARCH_WEB:query`
- Time: `[CURRENT_TIME]`

Begin your response now. Use your tools wisely."""

# ═══════════════════════════ ACTION PARSER ═════════════════════

def parse_and_apply_action(raw: str, user_id: int, mem: MemoryStore) -> tuple[str, bool]:
    # Buscar y ejecutar comandos SEARCH_WEB
    search_pattern = r'SEARCH_WEB:(.*?)(?:\n|$)'
    search_matches = re.findall(search_pattern, raw, re.IGNORECASE)
    
    for query in search_matches:
        query = query.strip()
        if query:
            logger.info(f"Ejecutando búsqueda web: {query}")
            search_results = perform_web_search(query)
            # Reemplazar el comando con los resultados
            raw = raw.replace(f"SEARCH_WEB:{query}", f"[Resultados de búsqueda: {query}]\n{search_results}")

    # Procesar acciones ARIA
    pattern = r"<ARIA_ACTION>(.*?)</ARIA_ACTION>"
    match = re.search(pattern, raw, re.DOTALL)
    if not match:
        return raw.strip(), False

    clean = (raw[: match.start()] + raw[match.end():]).strip()
    action_text = match.group(1).strip()

    try:
        data = json.loads(action_text)
        action = data.get("action", "")

        if action == "write_memory":
            content = data.get("content", "")
            if content:
                mem.write_memory(content)
                return clean, True

        elif action == "patch_memory":
            old = data.get("old_text", "")
            new = data.get("new_text", "")
            if old:
                mem.patch_memory(old, new)
                return clean, True

        elif action == "append_note":
            content = data.get("content", "")
            if content:
                current = mem.read_memory()
                section = "## Important Notes\n\n"
                if section in current:
                    updated = current.replace(
                        section,
                        section + f"- {content}\n",
                        1,
                    )
                    mem.write_memory(updated)
                return clean, True

        elif action == "set_reminder":
            reminder_text = data.get("reminder_text", "")
            reminder_time = data.get("reminder_time", "")
            recurrence = data.get("recurrence")
            if reminder_text and reminder_time:
                create_reminder(user_id, reminder_text, reminder_time, recurrence)
                return clean, True

    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error parsing action: {e}")

    return clean, False

# ═══════════════════════════ SCHEMAS ════════════════════════════

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class RegisterRequestV2(BaseModel):
    username: str
    email: str
    password: str

class VerifyEmailRequest(BaseModel):
    email: str
    code: str

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
    due_date:    Optional[str] = None

# ═══════════════════════════ AUTH ROUTES ═══════════════════════

@app.post("/auth/register")
async def register(req: RegisterRequest):
    # Validaciones básicas
    if len(req.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if "@" not in req.email or "." not in req.email.split("@")[-1]:
        raise HTTPException(400, "Invalid email")

    # Verificar que no existe ya el usuario
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (req.username.lower(), req.email.lower())
    ).fetchone()
    conn.close()
    if existing:
        raise HTTPException(400, "Username or email already exists")

    # Generar código y guardarlo
    code    = _generate_code()
    now     = datetime.now()
    expires = (now + timedelta(minutes=10)).isoformat()

    conn = get_db()
    # Borrar intentos previos del mismo email
    conn.execute("DELETE FROM email_verifications WHERE email = ?", (req.email.lower(),))
    conn.execute(
        """INSERT INTO email_verifications 
           (email, code, username, password, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (req.email.lower(), code, req.username.lower(),
         _hash_password(req.password), now.isoformat(), expires)
    )
    conn.commit()
    conn.close()

    # Enviar email
    sent = send_verification_email(req.email, code, req.username)
    if not sent:
        raise HTTPException(500, "Could not send verification email")

    return {"status": "verification_sent", "email": req.email.lower()}

@app.post("/auth/verify-email")
async def verify_email(req: VerifyEmailRequest):
    conn = get_db()
    row = conn.execute(
        """SELECT * FROM email_verifications 
           WHERE email = ? AND code = ? AND verified = 0""",
        (req.email.lower(), req.code.strip())
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(400, "Invalid or expired code")

    # Verificar expiración
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        conn.execute("DELETE FROM email_verifications WHERE email = ?", (req.email.lower(),))
        conn.commit()
        conn.close()
        raise HTTPException(400, "Code expired, please register again")

    # Crear usuario
    try:
        conn.execute(
            "INSERT INTO users (username, email, password, plan, created_at) VALUES (?,?,?,?,?)",
            (row["username"], row["email"], row["password"],
             "free", datetime.now().isoformat()),
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("UPDATE email_verifications SET verified = 1 WHERE email = ?", (req.email.lower(),))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(400, "Username or email already exists")
    finally:
        conn.close()

    MemoryStore(user_id, row["username"])
    token = _make_token(user_id, row["username"])
    return {"token": token, "username": row["username"], "plan": "free"}

@app.post("/auth/resend-code")
async def resend_code(email: str):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM email_verifications WHERE email = ? AND verified = 0",
        (email.lower(),)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "No pending verification for this email")

    code    = _generate_code()
    expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE email_verifications SET code = ?, expires_at = ? WHERE email = ?",
        (code, expires, email.lower())
    )
    conn.commit()
    conn.close()

    send_verification_email(email, code, row["username"])
    return {"status": "code_resent"}

@app.post("/auth/login")
async def login(req: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (req.username.lower(), _hash_password(req.password)),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid username or password")
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().isoformat(), row["id"]),
    )
    conn.commit()
    conn.close()

    token = _make_token(row["id"], row["username"])
    return {"token": token, "username": row["username"], "plan": row["plan"]}

@app.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "plan": user["plan"],
        "created_at": user["created_at"],
        "last_login": user["last_login"],
    }

def _notes_routes(app, get_db, get_current_user):
    from fastapi import Depends, HTTPException

    @app.get("/notes")
    async def get_notes(user: dict = Depends(get_current_user)):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM notes WHERE user_id = ? ORDER BY pinned DESC, updated_at DESC",
            (user["id"],)
        ).fetchall()
        conn.close()
        return {"notes": [dict(r) for r in rows]}

    @app.post("/notes")
    async def create_note(req: NoteCreateRequest, user: dict = Depends(get_current_user)):
        now = datetime.now().isoformat()
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO notes (user_id, title, content, color, pinned, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (user["id"], req.title, req.content, req.color, int(req.pinned), now, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        return dict(row)

    @app.put("/notes/{note_id}")
    async def update_note(note_id: int, req: NoteUpdateRequest, user: dict = Depends(get_current_user)):
        conn = get_db()
        if not conn.execute("SELECT id FROM notes WHERE id=? AND user_id=?", (note_id, user["id"])).fetchone():
            conn.close()
            raise HTTPException(404, "Note not found")
        updates = {k: v for k, v in req.dict().items() if v is not None}
        if "pinned" in updates:
            updates["pinned"] = int(updates["pinned"])
        updates["updated_at"] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(f"UPDATE notes SET {set_clause} WHERE id = ?", (*updates.values(), note_id))
        conn.commit()
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        conn.close()
        return dict(row)

    @app.delete("/notes/{note_id}")
    async def delete_note(note_id: int, user: dict = Depends(get_current_user)):
        conn = get_db()
        conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user["id"]))
        conn.commit()
        conn.close()
        return {"status": "deleted"}

def _tasks_routes(app, get_db, get_current_user):
    from fastapi import Depends, HTTPException

    @app.get("/tasks")
    async def get_tasks(user: dict = Depends(get_current_user)):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY completed ASC, due_date ASC, created_at DESC",
            (user["id"],)
        ).fetchall()
        conn.close()
        return {"tasks": [dict(r) for r in rows]}

    @app.post("/tasks")
    async def create_task(req: TaskCreateRequest, user: dict = Depends(get_current_user)):
        now = datetime.now().isoformat()
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO tasks (user_id, title, description, priority, due_date, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (user["id"], req.title, req.description, req.priority, req.due_date, now, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        return dict(row)

    @app.put("/tasks/{task_id}")
    async def update_task(task_id: int, req: TaskUpdateRequest, user: dict = Depends(get_current_user)):
        conn = get_db()
        if not conn.execute("SELECT id FROM tasks WHERE id=? AND user_id=?", (task_id, user["id"])).fetchone():
            conn.close()
            raise HTTPException(404, "Task not found")
        updates = {k: v for k, v in req.dict().items() if v is not None}
        if "completed" in updates:
            updates["completed"] = int(updates["completed"])
        updates["updated_at"] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(f"UPDATE tasks SET {set_clause} WHERE id = ?", (*updates.values(), task_id))
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        conn.close()
        return dict(row)

    @app.delete("/tasks/{task_id}")
    async def delete_task(task_id: int, user: dict = Depends(get_current_user)):
        conn = get_db()
        conn.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user["id"]))
        conn.commit()
        conn.close()
        return {"status": "deleted"}

    @app.get("/reminders")
    async def get_reminders(user: dict = Depends(get_current_user)):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM reminders WHERE user_id = ? AND completed = 0 ORDER BY reminder_time ASC",
            (user["id"],)
        ).fetchall()
        conn.close()
        return {"reminders": [dict(r) for r in rows]}

# ═══════════════════════════ REMINDER ACK ENDPOINT ═════════════════════

@app.post("/reminder/ack/{reminder_id}")
async def ack_reminder(reminder_id: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT user_id FROM reminders WHERE id = ?", (reminder_id,)).fetchone()
    if not row or row["user_id"] != user["id"]:
        conn.close()
        raise HTTPException(404, "Recordatorio no encontrado")
    conn.close()
    complete_reminder(reminder_id)
    return {"status": "ok", "message": "Recordatorio confirmado"}

# ═══════════════════════════ CHAT ROUTE ════════════════════════
"""
Chat con ollama
@app.post("/chat")
async def chat(req: ChatRequest, user: dict = Depends(get_current_user)):
    if not req.message.strip():
        raise HTTPException(400, "Empty message")

    user_id  = user["id"]
    username = user["username"]
    mem      = MemoryStore(user_id, username)
    system   = build_system_prompt(user, mem)

    messages = [{"role": "system", "content": system}]
    messages.extend([{"role": m["role"], "content": m["content"]} for m in req.history[-20:]])
    messages.append({"role": "user", "content": req.message})

    payload = {
        "model":   MODEL_NAME,
        "messages": messages,
        "stream":  True,   # ← streaming activado
        "options": {"temperature": 0.1, "top_p": 0.9},
    }

    async def generate():
        full_text = ""
        try:
            async with httpx.AsyncClient(timeout=180) as c:
                async with c.stream("POST", f"{OLLAMA_URL}/api/chat", json=payload) as r:
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("message", {}).get("content", "")
                            full_text += token
                            # Enviar cada token como SSE
                            yield f"data: {json.dumps({'token': token})}\n\n"
                            if chunk.get("done"):
                                break
                        except json.JSONDecodeError:
                            continue

            # Post-procesamiento una vez terminado el stream
            clean_text, memory_updated = parse_and_apply_action(full_text, user_id, mem)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean_text = clean_text.replace("[CURRENT_TIME]", now_str)
            final_response = check_and_send_reminders_in_chat(user_id, clean_text)
            mem.append_history(req.message, final_response)

            # Evento final con metadata
            yield f"data: {json.dumps({'done': True, 'response': final_response, 'memory_updated': memory_updated})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",   # importante para nginx
            "Access-Control-Allow-Origin": "*",
        },
    )
""" 

@app.post("/chat")
async def chat(req: ChatRequest, user: dict = Depends(get_current_user)):
    if not req.message.strip():
        raise HTTPException(400, "Empty message")

    user_id  = user["id"]
    username = user["username"]
    mem      = MemoryStore(user_id, username)
    system   = build_system_prompt(user, mem)

    # Nota: Groq ya maneja el historial dentro de los mensajes, 
    # pero tu lógica de build_system_prompt ya lo incluye en el texto.
    # Por lo tanto, pasamos el mensaje directo para evitar redundancia.

    async def generate():
        full_text = ""
        try:
            # Llamamos a nuestra función de streaming de Groq
            async for token in call_groq_stream(req.message, system):
                full_text += token
                # Enviar cada token a Flutter
                yield f"data: {json.dumps({'token': token})}\n\n"

            # --- Post-procesamiento (Igual que antes pero optimizado) ---
            # 1. Ejecutar acciones (Memoria, Recordatorios, Búsqueda Web)
            clean_text, memory_updated = parse_and_apply_action(full_text, user_id, mem)
            
            # 2. Reemplazar tiempo
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean_text = clean_text.replace("[CURRENT_TIME]", now_str)
            
            # 3. Revisar recordatorios y guardar historial
            final_response = check_and_send_reminders_in_chat(user_id, clean_text)
            mem.append_history(req.message, final_response)

            # 4. Evento final con la respuesta limpia y acciones aplicadas
            yield f"data: {json.dumps({'done': True, 'response': final_response, 'memory_updated': memory_updated})}\n\n"

        except Exception as e:
            logger.error(f"Error en streaming de Groq: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )

# ═══════════════════════════ MEMORY ROUTES ═════════════════════

@app.get("/memory")
async def get_memory(user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    return {"memory": mem.read_memory()}

@app.put("/memory")
async def write_memory(req: MemoryWriteRequest, user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    mem.write_memory(req.content)
    return {"status": "saved"}

@app.patch("/memory")
async def patch_memory(req: MemoryPatchRequest, user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    ok = mem.patch_memory(req.old_text, req.new_text)
    if not ok:
        raise HTTPException(400, "Text not found in memory")
    return {"status": "patched"}

@app.delete("/memory")
async def clear_memory(user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    mem.write_memory(
        "# ARIA Long-Term Memory\n\n"
        "## User Information\n\n"
        "## Preferences\n\n"
        "## Ongoing Tasks\n\n"
        "## Important Notes\n\n"
    )
    return {"status": "memory cleared"}

@app.get("/memory/history")
async def get_history(limit: int = 30, user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    return {"history": mem.read_history(last_n=limit)}

@app.delete("/memory/history")
async def clear_history(user: dict = Depends(get_current_user)):
    mem = MemoryStore(user["id"], user["username"])
    mem.history_file.write_text("# ARIA Conversation History\n\n", encoding="utf-8")
    return {"status": "history cleared"}

_notes_routes(app, get_db, get_current_user)
_tasks_routes(app, get_db, get_current_user)

# ═══════════════════════════ HEALTH ════════════════════════════

@app.get("/health")
async def health():
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
            tags = r.json().get("models", [])
            model_ready = any(MODEL_NAME in m.get("name", "") for m in tags)
    except Exception:
        return {"status": "ok", "aria": "online", "ollama": "disconnected",
                "model": MODEL_NAME, "model_ready": False}

    return {
        "status": "ok",
        "aria": "online",
        "ollama": "connected",
        "model": MODEL_NAME,
        "model_ready": model_ready,
    }

# ═══════════════════════════ ENTRY POINT ═══════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)