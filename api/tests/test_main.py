"""
NAC Policy Engine — Unit Testler
pytest + httpx AsyncClient kullanır.
DB (asyncpg) ve Redis gerçek bağlantı gerektirmez — mock'lanır.
"""

import hashlib
import json
import pytest
import bcrypt
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

import sys
import os

# api/ dizinini path'e ekle (tests/ altından import için)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main


# ---------------------------------------------------------------------------
# Yardımcı: DB ve Redis mock'ları oluştur
# ---------------------------------------------------------------------------

def make_db_mock(fetchrow_return=None, fetch_return=None, execute_return=None):
    """asyncpg Pool + Connection mock'u döner."""
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=fetchrow_return)
    mock_conn.fetch    = AsyncMock(return_value=fetch_return or [])
    mock_conn.execute  = AsyncMock(return_value=execute_return)

    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
    return mock_pool, mock_conn


def make_redis_mock(get_return=None):
    """aioredis mock'u döner."""
    r = AsyncMock()
    r.get    = AsyncMock(return_value=get_return)
    r.incr   = AsyncMock(return_value=1)
    r.expire = AsyncMock()
    r.delete = AsyncMock()
    r.ttl    = AsyncMock(return_value=120)
    r.ping   = AsyncMock()
    r.setex  = AsyncMock()
    r.sadd   = AsyncMock()
    r.srem   = AsyncMock()
    r.smembers = AsyncMock(return_value=set())
    return r


# ---------------------------------------------------------------------------
# 1. Pure Fonksiyonlar
# ---------------------------------------------------------------------------

class TestVerifyPassword:
    def test_cleartext_correct(self):
        assert main.verify_password("sifre123", "Cleartext-Password", "sifre123") is True

    def test_cleartext_wrong(self):
        assert main.verify_password("yanlis", "Cleartext-Password", "sifre123") is False

    def test_md5_correct(self):
        hashed = hashlib.md5("sifre123".encode()).hexdigest()
        assert main.verify_password("sifre123", "MD5-Password", hashed) is True

    def test_md5_wrong(self):
        hashed = hashlib.md5("sifre123".encode()).hexdigest()
        assert main.verify_password("yanlis", "MD5-Password", hashed) is False

    def test_bcrypt_correct(self):
        hashed = bcrypt.hashpw("sifre123".encode(), bcrypt.gensalt()).decode()
        assert main.verify_password("sifre123", "Crypt-Password", hashed) is True

    def test_bcrypt_wrong(self):
        hashed = bcrypt.hashpw("sifre123".encode(), bcrypt.gensalt()).decode()
        assert main.verify_password("yanlis", "Crypt-Password", hashed) is False

    def test_unknown_attribute_returns_false(self):
        assert main.verify_password("sifre", "Unknown-Attr", "sifre") is False


class TestIsMac:
    def test_valid_colon(self):
        assert main.is_mac("aa:bb:cc:dd:ee:ff") is True

    def test_valid_hyphen(self):
        assert main.is_mac("AA-BB-CC-DD-EE-FF") is True

    def test_uppercase(self):
        assert main.is_mac("AA:BB:CC:DD:EE:FF") is True

    def test_invalid_short(self):
        assert main.is_mac("aa:bb:cc:dd:ee") is False

    def test_invalid_username(self):
        assert main.is_mac("admin") is False

    def test_invalid_empty(self):
        assert main.is_mac("") is False


class TestExtract:
    def test_format_a_list(self):
        body = {"User-Name": [{"type": "string", "value": "alice"}]}
        assert main.extract(body, "User-Name") == "alice"

    def test_format_b_dict(self):
        body = {"User-Name": {"type": "string", "value": ["alice"]}}
        assert main.extract(body, "User-Name") == "alice"

    def test_direct_value(self):
        body = {"User-Name": "alice"}
        assert main.extract(body, "User-Name") == "alice"

    def test_snake_case_fallback(self):
        body = {"user_name": "alice"}
        assert main.extract(body, "User-Name") == "alice"

    def test_missing_key_returns_default(self):
        assert main.extract({}, "User-Name", "varsayilan") == "varsayilan"

    def test_value_as_list(self):
        body = {"User-Name": [{"type": "string", "value": ["alice"]}]}
        assert main.extract(body, "User-Name") == "alice"


# ---------------------------------------------------------------------------
# 2. /health Endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_ok():
    mock_pool, mock_conn = make_db_mock()
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.get("/health")

    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_db_error():
    mock_pool, mock_conn = make_db_mock()
    mock_conn.fetchval = AsyncMock(side_effect=Exception("DB bağlanamadı"))
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.get("/health")

    assert r.status_code == 503
    data = r.json()
    assert data["db"] == "error"
    assert data["status"] == "degraded"


# ---------------------------------------------------------------------------
# 3. POST /auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auth_success_md5():
    hashed = hashlib.md5("admin123".encode()).hexdigest()
    mock_pool, _ = make_db_mock(fetchrow_return={"attribute": "MD5-Password", "value": hashed})
    mock_redis = make_redis_mock(get_return=None)  # rate-limit sayacı yok

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/auth", json={"username": "admin", "password": "admin123"})

    assert r.status_code == 200
    assert r.json()["code"] == 2  # Access-Accept


@pytest.mark.asyncio
async def test_auth_wrong_password():
    hashed = hashlib.md5("admin123".encode()).hexdigest()
    mock_pool, _ = make_db_mock(fetchrow_return={"attribute": "MD5-Password", "value": hashed})
    mock_redis = make_redis_mock(get_return=None)

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/auth", json={"username": "admin", "password": "yanlis"})

    assert r.status_code == 401


@pytest.mark.asyncio
async def test_auth_user_not_found():
    mock_pool, _ = make_db_mock(fetchrow_return=None)
    mock_redis = make_redis_mock(get_return=None)

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/auth", json={"username": "yok", "password": "bir_seyler"})

    assert r.status_code == 401


@pytest.mark.asyncio
async def test_auth_rate_limited():
    mock_pool, _ = make_db_mock()
    # Sayaç RATE_LIMIT_MAX (5) değerinde
    mock_redis = make_redis_mock(get_return=str(main.RATE_LIMIT_MAX))

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/auth", json={"username": "admin", "password": "admin123"})

    assert r.status_code == 401
    assert "Rate limited" in r.json()["detail"]


@pytest.mark.asyncio
async def test_auth_missing_fields():
    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/auth", json={"username": "admin"})  # password yok

    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 4. POST /authorize
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authorize_known_user_employee():
    """employee kullanıcısı → VLAN 20"""
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    # İlk fetchrow → radusergroup (grup)
    # İkinci fetchrow → radcheck (şifre hash)
    mock_conn.fetchrow = AsyncMock(side_effect=[
        {"groupname": "employee"},
        {"attribute": "MD5-Password", "value": "hash123"},
    ])
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/authorize", json={"User-Name": "employee"})

    assert r.status_code == 200
    assert r.json()["reply:Tunnel-Private-Group-Id"] == "20"


@pytest.mark.asyncio
async def test_authorize_known_mac_employee():
    """Bilinen MAC → radusergroup'ta employee → VLAN 20"""
    mac = "aa:bb:cc:dd:ee:ff"
    mock_pool = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(side_effect=[
        {"groupname": "employee"},                              # radusergroup
        {"attribute": "Cleartext-Password", "value": mac},     # radcheck
    ])
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/authorize", json={"User-Name": mac})

    assert r.status_code == 200
    assert r.json()["reply:Tunnel-Private-Group-Id"] == "20"


@pytest.mark.asyncio
async def test_authorize_unknown_mac_guest_vlan():
    """Bilinmeyen MAC → guest VLAN 30 (fallback politikası)"""
    mac = "ff:ee:dd:cc:bb:aa"
    mock_pool = MagicMock()
    mock_conn = AsyncMock()
    # radusergroup'ta kayıt yok → None, radcheck'te de yok → None
    mock_conn.fetchrow = AsyncMock(side_effect=[None, None])
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/authorize", json={"User-Name": mac})

    assert r.status_code == 200
    assert r.json()["reply:Tunnel-Private-Group-Id"] == "30"  # guest VLAN


# ---------------------------------------------------------------------------
# 5. POST /accounting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_accounting_start():
    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()

    body = {
        "User-Name": "admin",
        "Acct-Session-Id": "sess001",
        "Acct-Status-Type": "Start",
        "NAS-IP-Address": "10.0.0.1",
    }

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/accounting", json=body)

    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    mock_redis.setex.assert_called_once()   # Redis'e cache yazıldı
    mock_redis.sadd.assert_called_once()    # active_sessions'a eklendi


@pytest.mark.asyncio
async def test_accounting_stop():
    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()

    body = {
        "User-Name": "admin",
        "Acct-Session-Id": "sess001",
        "Acct-Status-Type": "Stop",
        "Acct-Session-Time": "300",
        "Acct-Input-Octets": "1024",
        "Acct-Output-Octets": "2048",
    }

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/accounting", json=body)

    assert r.status_code == 200
    mock_redis.delete.assert_called()  # Redis'ten silindi
    mock_redis.srem.assert_called()    # active_sessions'dan çıkarıldı


@pytest.mark.asyncio
async def test_accounting_interim_update():
    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()

    body = {
        "User-Name": "admin",
        "Acct-Session-Id": "sess001",
        "Acct-Status-Type": "Interim-Update",
        "Acct-Session-Time": "60",
        "Acct-Input-Octets": "512",
        "Acct-Output-Octets": "1024",
    }

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.post("/accounting", json=body)

    assert r.status_code == 200


# ---------------------------------------------------------------------------
# 6. GET /users
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_users_list():
    mock_pool = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[
        {"username": "admin",    "groupname": "admin",    "active_sessions": 1},
        {"username": "employee", "groupname": "employee", "active_sessions": 0},
    ])
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
    mock_redis = make_redis_mock()

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.get("/users")

    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    assert data[0]["username"] == "admin"
    assert data[0]["group"] == "admin"
    assert data[0]["active_sessions"] == 1


# ---------------------------------------------------------------------------
# 7. GET /sessions/active
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sessions_active_empty():
    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()
    mock_redis.smembers = AsyncMock(return_value=set())

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.get("/sessions/active")

    assert r.status_code == 200
    assert r.json()["count"] == 0


@pytest.mark.asyncio
async def test_sessions_active_with_data():
    session_data = json.dumps({
        "session_id": "sess001",
        "username": "admin",
        "nas_ip": "10.0.0.1",
        "start": "2026-03-25T10:00:00+00:00",
    })

    mock_pool, _ = make_db_mock()
    mock_redis = make_redis_mock()
    mock_redis.smembers = AsyncMock(return_value={"sess001"})
    mock_redis.get = AsyncMock(return_value=session_data)

    with patch.object(main, "db_pool", mock_pool), \
         patch.object(main, "redis_cli", mock_redis):
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            r = await client.get("/sessions/active")

    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["sessions"][0]["username"] == "admin"
