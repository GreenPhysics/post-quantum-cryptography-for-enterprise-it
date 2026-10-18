# PQC Book Part III, Chapter 19 - PostgreSQL rebuilt on the Amazon Linux 2023 base.
# The point of this file is one library: the AL2023 postgresql package links the OpenSSL that AL2023 ships (3.5.7 at
# the time of writing), which negotiates X25519MLKEM768 by default. The stock postgres:17 image is Debian and links
# OpenSSL 3.0, which cannot. Same PostgreSQL major, different libssl - the only variable Chapter 19 changes.
#
# Build (Runbook 05, Step 2):  docker build --build-arg PG_MAJOR=17 -t pqc-postgres:17-al2023 .
# Runtime contract: same environment variables as the stock image (POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD),
# data at /var/lib/pgsql/data (the AL2023 package default, NOT /var/lib/postgresql/data), TLS material at /certs.

FROM public.ecr.aws/amazonlinux/amazonlinux:2023
ARG PG_MAJOR=17

RUN dnf -y install postgresql${PG_MAJOR}-server postgresql${PG_MAJOR}-contrib openssl \
 && dnf clean all \
 && rm -rf /var/cache/dnf \
 && mkdir -p /var/lib/pgsql/data /run/postgresql \
 && chown -R postgres:postgres /var/lib/pgsql /run/postgresql \
 && postgres --version && openssl version

ENV PGDATA=/var/lib/pgsql/data
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER postgres
EXPOSE 5432
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
