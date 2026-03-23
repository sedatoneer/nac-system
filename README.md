# NAC Sistemi — S3M Security Staj Değerlendirme Ödevi

Network Access Control (NAC) sistemi. RADIUS protokolü (RFC 2865/2866) tabanlı AAA mimarisi.

## Teknolojiler

| Servis | Image | Görev |
|--------|-------|-------|
| FreeRADIUS 3.2 | custom build | RADIUS sunucusu — auth/authz/acct |
| PostgreSQL 18 | postgres:18-alpine | Kullanıcı, grup, oturum veritabanı |
| Redis 8 | redis:8-alpine | Oturum önbelleği, rate-limit sayacı |
| FastAPI | python:3.13-slim | Policy engine — tüm iş mantığı |

## Mimari

```
radtest / radclient (test)
        │  UDP 1812/1813
        ▼
   FreeRADIUS
        │  HTTP (rlm_rest)
        ▼
   FastAPI :8000
        │
   ┌────┴────┐
PostgreSQL  Redis
```

**Akış:** Her RADIUS isteği → FreeRADIUS → FastAPI `/authorize` → PAP doğrulama → Access-Accept + VLAN atribütleri

## Kurulum

```bash
# 1. Repo'yu klonla
git clone <repo-url>
cd nac-system

# 2. Ortam değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle (şifreleri değiştir)

# 3. Sistemi başlat
docker compose up -d --build

# 4. Servis durumunu kontrol et
docker compose ps
```

## Test

### PAP Authentication

```bash
# Başarılı giriş — admin (VLAN 10)
docker exec nac-system-freeradius-1 radtest admin admin123 localhost 0 testing123

# Başarılı giriş — employee (VLAN 20)
docker exec nac-system-freeradius-1 radtest employee emp123 localhost 0 testing123

# Başarılı giriş — guest (VLAN 30)
docker exec nac-system-freeradius-1 radtest guest guest123 localhost 0 testing123

# Başarısız giriş
docker exec nac-system-freeradius-1 radtest admin yanlis localhost 0 testing123
```

### MAB (MAC Authentication Bypass)

```bash
# Bilinen MAC → employee VLAN 20
docker exec nac-system-freeradius-1 sh -c \
  "echo 'User-Name=aa:bb:cc:dd:ee:ff,User-Password=aa:bb:cc:dd:ee:ff,Calling-Station-Id=aa:bb:cc:dd:ee:ff' \
  | radclient localhost auth testing123"

# Bilinmeyen MAC → guest VLAN 30 (fallback politikası)
docker exec nac-system-freeradius-1 sh -c \
  "echo 'User-Name=ff:ee:dd:cc:bb:aa,User-Password=ff:ee:dd:cc:bb:aa,Calling-Station-Id=ff:ee:dd:cc:bb:aa' \
  | radclient localhost auth testing123"
```

### Accounting

```bash
# Oturum başlat (Start)
docker exec nac-system-freeradius-1 sh -c \
  "echo 'User-Name=admin,Acct-Session-Id=test001,Acct-Status-Type=Start,NAS-IP-Address=10.0.0.1' \
  | radclient localhost acct testing123"

# Ara güncelleme (Interim-Update)
docker exec nac-system-freeradius-1 sh -c \
  "echo 'User-Name=admin,Acct-Session-Id=test001,Acct-Status-Type=Interim-Update,Acct-Session-Time=60,Acct-Input-Octets=102400,Acct-Output-Octets=204800' \
  | radclient localhost acct testing123"

# Oturum kapat (Stop)
docker exec nac-system-freeradius-1 sh -c \
  "echo 'User-Name=admin,Acct-Session-Id=test001,Acct-Status-Type=Stop,Acct-Session-Time=300,Acct-Input-Octets=5242880,Acct-Output-Octets=10485760' \
  | radclient localhost acct testing123"

# Veritabanını kontrol et
docker exec nac-system-postgres-1 psql -U radius -d radius \
  -c "SELECT acctsessionid, username, acctsessiontime, acctstatustype FROM radacct;"
```

### FastAPI Endpoint'leri

```bash
# Sağlık kontrolü
curl http://localhost:8000/health

# Kullanıcı listesi
curl http://localhost:8000/users

# Kimlik doğrulama (direkt)
curl -X POST http://localhost:8000/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Aktif oturumlar (Redis)
curl http://localhost:8000/sessions/active

# API dokümantasyonu
open http://localhost:8000/docs
```

### Rate Limiting Testi

```bash
# 5 başarısız denemeden sonra 300 saniye blok
for i in 1 2 3 4 5 6; do
  curl -s -X POST http://localhost:8000/auth \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"yanlis"}'
  echo ""
done
```

## Kullanıcılar ve VLAN Ataması

| Kullanıcı | Şifre | Grup | VLAN |
|-----------|-------|------|------|
| admin | admin123 | admin | 10 |
| employee | emp123 | employee | 20 |
| guest | guest123 | guest | 30 |

## Güvenlik Notları

- Şifreler veritabanında MD5 hash olarak saklanır (API bcrypt destekler)
- `.env` dosyası git'e commit edilmez
- Üretim ortamında `clients.conf` sadece yetkili NAS IP'lerine izin vermeli
- Redis ve PostgreSQL portları dışarıya açılmamıştır

## Proje Yapısı

```
nac-system/
├── docker-compose.yml      # 4 servis, healthcheck, network
├── .env                    # Ortam değişkenleri (git'e eklenmez)
├── .env.example            # Örnek yapılandırma
├── postgres/
│   └── init.sql            # Şema + seed verisi
├── freeradius/
│   ├── Dockerfile          # Config izin düzeltmeli image
│   ├── clients.conf        # NAS listesi
│   ├── mods-enabled/
│   │   ├── sql             # PostgreSQL modülü
│   │   └── rest            # REST modülü (FastAPI entegrasyonu)
│   └── sites-enabled/
│       └── default         # Ana virtual server
└── api/
    ├── Dockerfile
    ├── requirements.txt
    └── main.py             # FastAPI policy engine (5 endpoint)
```
