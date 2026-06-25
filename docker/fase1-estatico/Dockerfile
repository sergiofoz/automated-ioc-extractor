FROM ubuntu:24.04

# Evitar interacciones durante apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias del sistema y compiladores
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    ssdeep \
    libimage-exiftool-perl \
    file \
    radare2 \
    python3 \
    python3-venv \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Configurar entorno virtual Python (PEP 668)
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Instalar herramientas Python
RUN pip install --no-cache-dir flare-floss avclass pefile

# Copiar binario capa estático
COPY capa /usr/local/bin/capa
RUN chmod +x /usr/local/bin/capa

# Crear usuario cape (UID 999)
RUN groupadd -g 999 cape && \
    useradd -r -u 999 -g cape -d /home/cape -m cape

# Preparar directorios de interfaz
RUN mkdir -p /input /output /rules && \
    chown -R cape:cape /input /output /rules /opt/venv

USER cape
WORKDIR /home/cape

CMD ["/bin/bash"]
