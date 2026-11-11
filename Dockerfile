FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE.txt ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --create-home --shell /usr/sbin/nologin sentinel

USER sentinel

EXPOSE 8000

# Pass AI_SENTINEL_API_KEY at runtime. The image does not contain a key.
CMD ["uvicorn", "ai_sentinel.api.gateway:app", "--host", "0.0.0.0", "--port", "8000"]
