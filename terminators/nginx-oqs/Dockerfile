# PQC TLS Sidecar: NGINX + OpenSSL 3 + OQS provider
# Multi-stage builds liboqs and oqs-provider, then assembles a small runtime.

# --- Build liboqs + oqs-provider -------------------------------------------------
FROM debian:bookworm AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ninja-build pkg-config ca-certificates \
    openssl libssl-dev wget && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# liboqs (only library, shared, distribution profile)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
WORKDIR /src/liboqs
RUN cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/oqs \
    -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON .
RUN ninja && ninja install

# oqs-provider
WORKDIR /src
RUN git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
WORKDIR /src/oqs-provider
RUN cmake -GNinja -DCMAKE_PREFIX_PATH=/opt/oqs -DCMAKE_INSTALL_PREFIX=/opt/oqs .
RUN ninja && ninja install

# --- Runtime ---------------------------------------------------------------------
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx openssl procps python3 python3-venv ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy OQS artifacts
COPY --from=build /opt/oqs /opt/oqs

# OpenSSL configuration to auto-load provider
COPY openssl.cnf /etc/ssl/openssl.cnf

# NGINX configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Tailer script
COPY tls_deny_tailer.py /opt/oqs/tls_deny_tailer.py

# Minimal virtualenv for tailer dependencies
RUN python3 -m venv /opt/oqs/venv && /opt/oqs/venv/bin/pip install --no-cache-dir requests

EXPOSE 443
# Use sh -lc so we can run nginx and the tailer in foreground (simple init pattern)
CMD ["/bin/sh","-lc","nginx -g 'daemon off;' & /opt/oqs/venv/bin/python /opt/oqs/tls_deny_tailer.py --error-log /var/log/nginx/error.log --events-url http://app:8080/events --policy-id default-pqc-policy"]
