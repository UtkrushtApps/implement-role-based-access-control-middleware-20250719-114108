#!/bin/bash
set -e

echo "[install.sh] Building Docker image..."
docker-compose build

echo "[install.sh] Starting services..."
docker-compose up -d

max_tries=25
attempt=0
until docker-compose exec fastapi-app curl --fail http://localhost:8000/docs >/dev/null 2>&1; do
  ((attempt++))
  if [ $attempt -ge $max_tries ]; then
      echo "[install.sh] App failed to start in time."
      exit 1
  fi
  echo "[install.sh] Waiting for app to become ready... ($attempt/$max_tries)"
  sleep 2
done

echo "[install.sh] FastAPI app is up and running."
