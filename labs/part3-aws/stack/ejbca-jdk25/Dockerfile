# PQC Book Part III — EJBCA Community on Temurin JDK 25 (the operating baseline from Chapter 21; appendix measurement).
# ONE variable changed from the pinned vendor image: the Java runtime. WildFly, EJBCA, Bouncy Castle and the entrypoint
# are the image Chapter 17 pinned by digest. Unsupported by Keyfactor (9.x: JDK 17/21) and WildFly 35 (17/21/23):
# measured first, adopted only if it starts and issues (fallback: Temurin 21).
#
# Build (CA host, ~/stack, tarball copied into ejbca-jdk25/ from vendor/, TEMURIN_SHA256 in .env from adoptium.net):
#   docker compose -f docker-compose.yml -f docker-compose.tls.yml -f docker-compose.jdk25.yml build ejbca
# The vendor image carries no gzip (measured 2026-10-04: "tar (child): gzip: Cannot exec"), so the tarball is
# extracted by ADD — BuildKit decompresses — after a COPY + sha256sum verification of the same file.
# Measure, in order: (a) java -version 25.0.4.1 and WildFly "started in"; (b) JDBC group via JAVA_OPTS_APPEND
# -Djavax.net.debug=ssl:handshake:verbose; (c) Chapter 19 Phase C (ML-DSA-65 db cert) on 25; (d) SunPKCS11 +
# fortanix_pkcs11.so with -Djava.security.debug=sunpkcs11 — does the JDK map CKM_ML_DSA (0x1D)?
ARG EJBCA_DIGEST=sha256:183b86af44b9b13e7cc8912c868f635aeb8dba6bf056ccbd4683b17626964d0a
FROM keyfactor/ejbca-ce@${EJBCA_DIGEST}

ARG TEMURIN_TGZ=OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz
ARG TEMURIN_SHA256
USER root
COPY ${TEMURIN_TGZ} /tmp/temurin.tar.gz
RUN test -n "${TEMURIN_SHA256}" && echo "${TEMURIN_SHA256}  /tmp/temurin.tar.gz" | sha256sum -c - && rm /tmp/temurin.tar.gz
ADD ${TEMURIN_TGZ} /opt/temurin-25/
RUN ln -s /opt/temurin-25/jdk-* /opt/jdk25 && /opt/jdk25/bin/java -version
ENV JAVA_HOME=/opt/jdk25
ENV PATH=/opt/jdk25/bin:${PATH}
USER 10001
