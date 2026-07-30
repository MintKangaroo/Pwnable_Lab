FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/pyproject.toml backend/requirements.txt ./
COPY backend/setup.py ./
COPY backend/pwnable_lab ./pwnable_lab
COPY backend/alembic.ini ./alembic.ini
COPY backend/migrations ./migrations

RUN pip install --no-cache-dir .

RUN addgroup --system plab && adduser --system --ingroup plab plab \
    && mkdir -p /data/binaries && chown -R plab:plab /data

USER plab
EXPOSE 8000

CMD ["uvicorn", "pwnable_lab.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
