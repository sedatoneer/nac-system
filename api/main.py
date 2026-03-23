"""
NAC Policy Engine — FastAPI
FreeRADIUS'ın rlm_rest modülü üzerinden çağırdığı policy engine.

Endpoint özeti:
  POST /auth            → Kullanıcı doğrulama + rate-limiting
  POST /authorize       → VLAN/policy atribütleri (rlm_rest authorize)
  POST /accounting      → Oturum verisi kaydet (rlm_rest accounting)
  GET  /users           → Kullanıcı listesi ve durum
  GET  /sessions/active → Redis'teki aktif oturumlar
  GET  /health          → Servis sağlığı (healthcheck için)
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

import asyncpg
import bcrypt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Response

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="NAC Policy Engine", version="1.0.0")

# ---- Konfigürasyon ----
DB_URL          = os.getenv("DATABASE_URL", "postgresql://radius:radius@postgres:5432/radius")
REDIS_URL       = os.getenv("REDIS_URL", "redis://redis:6379")
RATE_LIMIT_MAX  = int(os.getenv("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WIN  = int(os.getenv("RATE_LIMIT_WINDOW", "300"))  # saniye

# Grup → VLAN eşlemesi
VLAN_MAP = {
    "admin":    "10",
    "employee": "20",
    "guest":    "30",
}

# ---- Global bağlantı nesneleri ----
db_pool: asyncpg.Pool   = None
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
        # Format A: değer liste içinde
        if isinstance(item, list) and item:
            val = item[0].get("value", default) if isinstance(item[0], dict) else item[0]
        # Format B: değer doğrudan dict
        elif isinstance(item, dict):
            val = item.get("value", default)
        else:
            val = item
        # value kendisi liste olabilir: ["alice"] → "alice"
        if isinstance(val, list):
            return val[0] if val else default
        return val
    # Direkt çağrı için fallback (snake_case ve orijinal key)
    snake = attr.lower().replace("-", "_")
    return body.get(snake, body.get(attr, default))


def verify_password(plaintext: str, attribute: str, stored: str) -> bool:
    """Atribüt tipine göre şifre doğrulaması yapar."""
    if attribute == "Cleartext-Password":
        return plaintext == stored
    elif attribute == "MD5-Password":
        # PostgreSQL md5() ile aynı formatta: lowercase hex
        return hashlib.md5(plaintext.encode()).hexdigest() == stored
    elif attribute == "Crypt-Password":
        # bcrypt — API üzerinden oluşturulan kullanıcılar için
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    return False


def is_mac(value: str) -> bool:
    """MAC adresi formatını tespit et (MAB istekleri için)."""
    return bool(re.match(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$", value))


async def rate_limit_increment(key: str):
    """Başarısız deneme sayacını artır."""
    await redis_cli.incr(key)
    await redis_cli.expire(key, RATE_LIMIT_WIN)


# =============================================================
# Endpoint: /health
# =============================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


# =============================================================
# Endpoint: POST /auth
# Kullanıcı doğrulama + Redis rate-limiting
# FreeRADIUS'ın authenticate aşamasında veya direkt curl ile çağrılır.
# =============================================================

@app.post("/auth")
async def auth(body: dict):
    username = extract(body, "User-Name") or body.get("username")
    password = extract(body, "User-Password") or body.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username ve password zorunlu")

    # ---- Rate limiting (Redis) ----
    rl_key   = f"rl:{username}"
    attempts = await redis_cli.get(rl_key)
    if attempts and int(attempts) >= RATE_LIMIT_MAX:
        ttl = await redis_cli.ttl(rl_key)
        # HTTP 401 → FreeRADIUS rlm_rest bunu REJECT olarak yorumlar
        raise HTTPException(status_code=401,
                            detail=f"Rate limited. {ttl}s sonra tekrar dene.")

    # ---- Veritabanından kullanıcıyı getir ----
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
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

    # ---- Şifre doğrulama ----
    if verify_password(password, row["attribute"], row["value"]):
        await redis_cli.delete(rl_key)  # başarılı girişte sayacı sıfırla
        # HTTP 200 → FreeRADIUS rlm_rest bunu ACCEPT olarak yorumlar
        return {"code": 2, "message": "Access-Accept"}
    else:
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Hatalı şifre")


# =============================================================
# Endpoint: POST /authorize
# FreeRADIUS authorize aşamasında rlm_rest tarafından çağrılır.
# VLAN atribütlerini döner. MAB (MAC auth) desteği dahil.
# =============================================================

@app.post("/authorize")
async def authorize(body: dict):
    logger.debug("AUTHORIZE IN: %s", json.dumps(body, default=str))
    username = extract(body, "User-Name") or body.get("username")
    if not username:
        return {}

    # ---- Kullanıcının grubunu bul ----
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 ORDER BY priority LIMIT 1",
            username,
        )

    mab_request = is_mac(username)

    if not row:
        if mab_request:
            # Bilinmeyen MAC → guest VLAN (PDF: "reject veya guest VLAN" — biz guest seçiyoruz)
            vlan = VLAN_MAP["guest"]
        else:
            return {}  # normal kullanıcı ama grubu yok
    else:
        vlan = VLAN_MAP.get(row["groupname"], VLAN_MAP["guest"])

    # Şifre hash'ini al — FreeRADIUS PAP modülü bunu control listesiyle doğrular
    async with db_pool.acquire() as conn:
        pwd_row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    # ---- FreeRADIUS rlm_rest RESPONSE formatı ----
    # Önemli: nested dict/list değil, düz "list:Attr": "değer" formatı
    # "control:Attr" → FreeRADIUS iç listesi (şifre kontrolü için)
    # "reply:Attr"   → Access-Accept paketine eklenir (VLAN)
    response = {
        "reply:Tunnel-Type":             "13",  # 13 = VLAN
        "reply:Tunnel-Medium-Type":      "6",   # 6 = IEEE-802
        "reply:Tunnel-Private-Group-Id": vlan,
    }

    if pwd_row:
        # Bilinen kullanıcı: DB'deki hash ile PAP doğrulaması
        response[f"control:{pwd_row['attribute']}"] = pwd_row["value"]
    elif mab_request:
        # Bilinmeyen MAC: MAB convention'ı gereği User-Password = MAC adresi
        # Cleartext-Password olarak MAC'i set et → PAP doğrulayabilir
        response["control:Cleartext-Password"] = username

    logger.debug("AUTHORIZE OUT: %s", json.dumps(response, default=str))
    return response


# =============================================================
# Endpoint: POST /accounting
# FreeRADIUS accounting aşamasında rlm_rest tarafından çağrılır.
# Start/Interim-Update/Stop paketlerini işler.
# =============================================================

@app.post("/accounting")
async def accounting(body: dict):
    username       = extract(body, "User-Name",          "unknown")
    session_id     = extract(body, "Acct-Session-Id",    "")
    status_type    = extract(body, "Acct-Status-Type",   "")
    nas_ip         = extract(body, "NAS-IP-Address",     "")
    session_time   = int(extract(body, "Acct-Session-Time",    0) or 0)
    input_octets   = int(extract(body, "Acct-Input-Octets",    0) or 0)
    output_octets  = int(extract(body, "Acct-Output-Octets",   0) or 0)

    now = datetime.now(timezone.utc)

    async with db_pool.acquire() as conn:

        if status_type in ("Start", "1"):
            # Yeni oturum başladı → DB'ye yaz, Redis'e cache'le
            await conn.execute(
                """
                INSERT INTO radacct
                    (acctsessionid, username, nasipaddress, acctstarttime, acctstatustype)
                VALUES ($1, $2, $3, $4, 'Start')
                ON CONFLICT (acctsessionid) DO NOTHING
                """,
                session_id, username, nas_ip, now,
            )
            # Redis: 24 saat TTL ile aktif oturum cache'i
            session_data = {
                "session_id": session_id,
                "username":   username,
                "nas_ip":     nas_ip,
                "start":      now.isoformat(),
            }
            await redis_cli.setex(f"session:{session_id}", 86400, json.dumps(session_data))
            await redis_cli.sadd("active_sessions", session_id)

        elif status_type in ("Interim-Update", "3"):
            # Oturum devam ediyor → istatistikleri güncelle
            await conn.execute(
                """
                UPDATE radacct
                SET acctsessiontime  = $1,
                    acctinputoctets  = $2,
                    acctoutputoctets = $3,
                    acctstatustype   = 'Interim-Update',
                    acctupdatetime   = $4
                WHERE acctsessionid = $5
                """,
                session_time, input_octets, output_octets, now, session_id,
            )

        elif status_type in ("Stop", "2"):
            # Oturum bitti → DB'yi kapat, Redis'ten sil
            await conn.execute(
                """
                UPDATE radacct
                SET acctstoptime     = $1,
                    acctsessiontime  = $2,
                    acctinputoctets  = $3,
                    acctoutputoctets = $4,
                    acctstatustype   = 'Stop'
                WHERE acctsessionid = $5
                """,
                now, session_time, input_octets, output_octets, session_id,
            )
            await redis_cli.delete(f"session:{session_id}")
            await redis_cli.srem("active_sessions", session_id)

    return {"status": "ok"}


# =============================================================
# Endpoint: GET /users
# Kullanıcı listesi, grup bilgisi ve aktif oturum sayısı
# =============================================================

@app.get("/users")
async def users():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                rc.username,
                rug.groupname,
                COUNT(ra.radacctid) FILTER (WHERE ra.acctstatustype != 'Stop') AS active_sessions
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            LEFT JOIN radacct ra       ON rc.username = ra.username
            WHERE rc.attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            GROUP BY rc.username, rug.groupname
            ORDER BY rc.username
            """
        )
    return [
        {
            "username":        r["username"],
            "group":           r["groupname"],
            "active_sessions": r["active_sessions"] or 0,
        }
        for r in rows
    ]


# =============================================================
# Endpoint: GET /sessions/active
# Redis'teki aktif oturumları döner (hızlı sorgulama)
# =============================================================

@app.get("/sessions/active")
async def sessions_active():
    session_ids = await redis_cli.smembers("active_sessions")
    sessions = []
    for sid in session_ids:
        data = await redis_cli.get(f"session:{sid}")
        if data:
            sessions.append(json.loads(data))

    return {"count": len(sessions), "sessions": sessions}
