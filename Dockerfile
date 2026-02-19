FROM python:3.13-slim

LABEL authors="nak"
LABEL sprint="1"
LABEL project="crypto_nak2"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt


COPY src /app/src
COPY README.md /app/README.md


CMD ["pytest", "-q"]
