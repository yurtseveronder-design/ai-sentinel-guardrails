FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir .

ENV PYTHONPATH=src

EXPOSE 8000

CMD ["uvicorn", "ai_sentinel.api.gateway:app", "--host", "0.0.0.0", "--port", "8000"]