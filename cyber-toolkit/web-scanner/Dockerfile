FROM python:3.11-slim

# Install requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY web-scanner /app/web-scanner

RUN python3 -m pip install --no-cache-dir requests

# expose nothing; this container is CLI-oriented
ENTRYPOINT [“python3”, “/app/web-scanner/scanner.py”]
