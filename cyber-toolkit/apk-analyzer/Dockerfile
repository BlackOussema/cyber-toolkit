FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Install apktool
RUN wget -q -O /usr/local/bin/apktool https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    && chmod +x /usr/local/bin/apktool

# Install jadx (binary)
RUN wget -q -O /tmp/jadx.zip https://github.com/skylot/jadx/releases/latest/download/jadx-zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip || true

# Copy analyzer script
COPY apk-analyzer /opt/apk-analyzer
WORKDIR /opt/apk-analyzer
RUN python3 -m pip install --no-cache-dir requests

ENTRYPOINT [“python3”, “/opt/apk-analyzer/analyze.py”]
