# One image serves both the API and the dashboard; docker-compose picks the command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FASTEMBED_CACHE_PATH=/app/.data/models \
    RAGSENTRY_INDEX_DIR=/app/.data/faiss_index

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY .streamlit ./.streamlit
RUN pip install .

RUN useradd --create-home --uid 1000 app && mkdir -p /app/.data && chown -R app /app/.data
USER app

EXPOSE 8000 8501
CMD ["uvicorn", "ragsentry.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
