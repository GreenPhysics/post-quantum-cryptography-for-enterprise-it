#!/bin/bash
# Entrypoint for the AL2023-based PostgreSQL image (Chapter 19). Runs as the postgres user.
# First start: initdb, TLS-only host access (hostssl), scram-sha-256, create the application role and database.
# Every start after that: just run the server. The certificate and key are read from /certs at each start, so a
# certificate swap (Runbook 05, Phase C: the ML-DSA-65 server certificate) is a file change and a restart, not a re-init.
set -euo pipefail

: "${POSTGRES_DB:=ejbca}"
: "${POSTGRES_USER:=ejbca}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"
: "${PGDATA:=/var/lib/pgsql/data}"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "entrypoint: initializing $PGDATA"
  initdb -D "$PGDATA" --username=postgres --pwfile=<(printf '%s\n' "$POSTGRES_PASSWORD") \
         --auth-local=peer --auth-host=scram-sha-256 >/dev/null

  cat >> "$PGDATA/postgresql.conf" <<EOF

# --- PQC Book Part III, Chapter 19 ---
listen_addresses = '*'
password_encryption = scram-sha-256
ssl = on
ssl_cert_file = '/certs/server.crt'
ssl_key_file = '/certs/server.key'
ssl_min_protocol_version = 'TLSv1.3'
EOF

  # Local (socket) access by peer identity for the entrypoint itself; every TCP client must use TLS.
  cat > "$PGDATA/pg_hba.conf" <<EOF
local   all   all                 peer
hostssl all   all   0.0.0.0/0     scram-sha-256
hostssl all   all   ::/0          scram-sha-256
EOF

  # Bootstrap on the socket only, with TLS off (certificates are not needed to create a role).
  pg_ctl -D "$PGDATA" -o "-c listen_addresses='' -c ssl=off" -w start >/dev/null
  psql -v ON_ERROR_STOP=1 --username=postgres --dbname=postgres <<EOF
CREATE ROLE "$POSTGRES_USER" LOGIN PASSWORD '$POSTGRES_PASSWORD';
CREATE DATABASE "$POSTGRES_DB" OWNER "$POSTGRES_USER";
EOF
  pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null
  echo "entrypoint: initialized; role $POSTGRES_USER and database $POSTGRES_DB created"
fi

echo "entrypoint: $(postgres --version) linked against $(openssl version)"
exec postgres -D "$PGDATA"
