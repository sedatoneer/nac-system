FROM python:3.13-slim

WORKDIR /app

# Bağımlılıkları önce kopyala (layer cache için)
COPY requirements.txt .
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Uvicorn ile FastAPI'yi başlat
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
