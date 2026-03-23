"""
NAC Policy Engine — FastAPI
FreeRADIUS'ın rlm_rest modülü üzerinden çağırdığı policy engine.

Endpoint özeti:
  POST /auth      → Kullanıcı doğrulama
  POST /authorize → VLAN/policy atribütleri (rlm_rest authorize)
  GET  /users     → Kullanıcı listesi
  GET  /health    → Servis sağlığı (healthcheck için)
"""

import hashlib
import json
import logging
import os

import asyncpg
import bcrypt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="NAC Policy Engine", version="0.1.0")

# ---- Konfigürasyon ----
DB_URL    = os.getenv("DATABASE_URL", "postgresql://radius:radius@postgres:5432/radius")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

# Grup → VLAN eşlemesi
VLAN_MAP = {
    "admin":    "10",
    "employee": "20",
    "guest":    "30",
}

# ---- Global bağlantı nesneleri ----
db_pool: asyncpg.Pool    = None
redis_cli: aioredis.Redis = None


# =============================================================
# Uygulama yaşam döngüsü
# =============================================================

@app.on_event("startup")
async def startup():
    global db_pool, redis_cli
    db_pool   = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    redis_cli = await aioredis.from_url(REDIS_URL, decode_responses=True)


@app.on_event("shutdown")
async def shutdown():
    await db_pool.close()
    await redis_cli.aclose()


# =============================================================
# Yardımcı fonksiyonlar
# =============================================================

def extract(body: dict, attr: str, default=None):
    """
    FreeRADIUS rlm_rest JSON formatından atribüt değeri çıkarır.

    FreeRADIUS 3.x rlm_rest iki farklı format gönderebilir:
      Format A (list): {"User-Name": [{"type": "string", "value": "alice"}]}
      Format B (dict): {"User-Name": {"type": "string", "value": ["alice"]}}

    Direkt API testi için fallback:
      {"username": "alice"}
    """
    if attr in body:
        item = body[attr]
        if isinstance(item, list) and item:
            val = item[0].get("value", default) if isinstance(item[0], dict) else item[0]
        elif isinstance(item, dict):
            val = item.get("value", default)
        else:
            val = item
        if isinstance(val, list):
            return val[0] if val else default
        return val
    snake = attr.lower().replace("-", "_")
    return body.get(snake, body.get(attr, default))


def verify_password(plaintext: str, attribute: str, stored: str) -> bool:
    """Atribüt tipine göre şifre doğrulaması yapar."""
    if attribute == "Cleartext-Password":
        return plaintext == stored
    elif attribute == "MD5-Password":
        return hashlib.md5(plaintext.encode()).hexdigest() == stored
    elif attribute == "Crypt-Password":
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    return False


# =============================================================
# Endpoint: /health
# =============================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


# =============================================================
# Endpoint: POST /auth
# Kullanıcı doğrulama — FreeRADIUS authenticate aşaması veya direkt curl
# =============================================================

@app.post("/auth")
async def auth(body: dict):
    username = extract(body, "User-Name") or body.get("username")
    password = extract(body, "User-Password") or body.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username ve password zorunlu")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    if not row:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

    if verify_password(password, row["attribute"], row["value"]):
        return {"code": 2, "message": "Access-Accept"}
    else:
        raise HTTPException(status_code=401, detail="Hatalı şifre")


# =============================================================
# Endpoint: POST /authorize
# FreeRADIUS authorize aşamasında rlm_rest tarafından çağrılır.
# VLAN atribütlerini döner.
# =============================================================

@app.post("/authorize")
async def authorize(body: dict):
    logger.debug("AUTHORIZE IN: %s", json.dumps(body, default=str))
    username = extract(body, "User-Name") or body.get("username")
    if not username:
        return {}

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 ORDER BY priority LIMIT 1",
            username,
        )

    if not row:
        return {}

    vlan = VLAN_MAP.get(row["groupname"], VLAN_MAP["guest"])

    async with db_pool.acquire() as conn:
        pwd_row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    response = {
        "reply:Tunnel-Type":             "13",
        "reply:Tunnel-Medium-Type":      "6",
        "reply:Tunnel-Private-Group-Id": vlan,
    }

    if pwd_row:
        response[f"control:{pwd_row['attribute']}"] = pwd_row["value"]

    logger.debug("AUTHORIZE OUT: %s", json.dumps(response, default=str))
    return response


# =============================================================
# Endpoint: GET /users
# =============================================================

@app.get("/users")
async def users():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT rc.username, rug.groupname
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            WHERE rc.attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            ORDER BY rc.username
            """
        )
    return [{"username": r["username"], "group": r["groupname"]} for r in rows]
