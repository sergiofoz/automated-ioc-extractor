FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-dev \
    build-essential \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python dependencies for Volatility3
RUN pip install --no-cache-dir pefile capstone yara-python pycryptodome

# Create cape user (UID 999, same as host)
RUN groupadd -g 999 cape && \
    useradd -r -u 999 -g cape -d /home/cape -m cape

# Prepare directories
RUN mkdir -p /dumps /output /plugins /volatility3 && \
    chown -R cape:cape /dumps /output /plugins /volatility3 /opt/venv

USER cape
WORKDIR /home/cape

# Copy Volatility3 and external plugins
COPY --chown=cape:cape tools/volatility3 /volatility3
COPY --chown=cape:cape tools/volatility-plugins /plugins/volatility-plugins
COPY --chown=cape:cape tools/check_spoof /plugins/check_spoof
COPY --chown=cape:cape tools/modex /plugins/modex

# Entrypoint: invoke vol.py with all plugin paths pre-configured
ENTRYPOINT ["python3", "/volatility3/vol.py", \
            "-p", "/plugins/volatility-plugins", \
            "-p", "/plugins/check_spoof", \
            "-p", "/plugins/modex"]
