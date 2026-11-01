FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iptables nmap curl file binutils chromium && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 mitigata
WORKDIR /app
COPY scripts/install_tools.py /tmp/install_tools.py
RUN python /tmp/install_tools.py
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY mitigata ./mitigata
RUN pip install --no-cache-dir --no-deps . && mkdir /data && chown mitigata:mitigata /data
USER mitigata
EXPOSE 8765
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=2).read()"
ENTRYPOINT ["python", "-m", "mitigata"]
CMD ["serve", "--listen-container", "--output", "/data"]
