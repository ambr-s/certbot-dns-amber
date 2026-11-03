FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/ambr-s/certbot-dns-amber" \
      org.opencontainers.image.description="Certbot with the scoped amber.systems DNS authenticator"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/certbot-dns-amber
COPY pyproject.toml README.md ./
COPY src/certbot_dns_amber/ ./src/certbot_dns_amber/
RUN python -m pip install --no-cache-dir . \
    && python -m pip check \
    && rm -rf /opt/certbot-dns-amber

WORKDIR /etc/letsencrypt
ENTRYPOINT ["certbot"]
CMD ["--help"]
