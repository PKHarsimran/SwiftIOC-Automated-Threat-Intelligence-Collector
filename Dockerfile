FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY swiftioc ./swiftioc
RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home swiftioc \
    && mkdir -p /data \
    && chown swiftioc:swiftioc /data
COPY --chown=swiftioc:swiftioc sources.example.yml /app/sources.yml

USER 10001
VOLUME ["/data"]
HEALTHCHECK --interval=5m --timeout=15s --retries=2 CMD ["swiftioc", "--self-test"]
ENTRYPOINT ["swiftioc"]
CMD ["--sources", "/app/sources.yml", "--out-dir", "/data", "--persist-feed", "--max-age-days", "30", "--max-store", "10000"]
