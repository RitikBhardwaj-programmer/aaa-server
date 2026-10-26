# Self-service portal. Flask's built-in server: lab only, production needs a real WSGI server.
FROM python:3.12.14-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# radclient (RFC 5176 Disconnect-Request), same package as the tests image
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends freeradius-utils \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin portal
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY *.py blocklist.txt ./
COPY templates/ templates/
COPY static/ static/
COPY tests/ tests/
USER portal
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8081/login', timeout=3)" || exit 1
CMD ["flask", "--app", "app", "run", "--host", "0.0.0.0", "--port", "8081"]
