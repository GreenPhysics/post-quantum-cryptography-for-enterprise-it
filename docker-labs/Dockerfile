# PQC for Enterprise IT — Lab Companion container
#
# Build context is the REPO ROOT (see docker-compose.yml / the GitHub
# workflow): the image needs both labs/ and docker-labs/.
#
# Stage 1 compiles the exact OpenSSL version the book pins, so the
# transcripts a reader generates match the text regardless of what their
# distro ships. Multi-arch: works on amd64 and arm64.

ARG OPENSSL_VERSION=3.5.0

# ---------------------------------------------------------------- stage 1
FROM debian:trixie-slim AS build
ARG OPENSSL_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" && \
    tar -xzf /tmp/openssl.tar.gz -C /tmp
RUN cd /tmp/openssl-${OPENSSL_VERSION} && \
    ./Configure --prefix=/opt/openssl --libdir=lib no-docs && \
    make -j"$(nproc)" && make install_sw install_ssldirs
    # install_ssldirs matters: without it there is no default openssl.cnf and
    # every bare `openssl req` fails — discovered live in sandbox validation.

# ---------------------------------------------------------------- stage 2
FROM debian:trixie-slim
COPY --from=build /opt/openssl /opt/openssl
ENV PATH="/opt/openssl/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 procps && \
    rm -rf /var/lib/apt/lists/*

COPY labs/        /opt/pqc/labs/
COPY docker-labs/ /opt/pqc/docker-labs/
RUN chmod +x /opt/pqc/labs/*.sh /opt/pqc/docker-labs/*.sh

EXPOSE 8080
WORKDIR /opt/pqc
ENTRYPOINT ["/opt/pqc/docker-labs/entrypoint.sh"]
