# Part III — Runbook 05: Post-quantum PostgreSQL (Chapter 19)

> **AS MEASURED 2026-09-26 — read this box before the steps below.** The runbook as written assumed PostgreSQL 17 would negotiate the hybrid once its OpenSSL could. It cannot: 17's `ssl_ecdh_curve` resolves names in OpenSSL's EC-curve table (`ECDH: unrecognized curve name: X25519MLKEM768`) and defaults to `prime256v1`, so every connection on either 17 image was P-256. The stack moved to **PostgreSQL 18.6** (`postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722`, Debian 13, OpenSSL 3.5.7) by `pg_dump`/`pg_restore` onto a new volume (`pgdata18:/var/lib/postgresql`), and the TLS overlay sets `ssl_groups=X25519MLKEM768:X25519:prime256v1`. Three further corrections: (1) `-brief` does not print the negotiated group on this OpenSSL build — test groups by SINGLE-GROUP OFFERS (`-groups X25519MLKEM768` succeeds/fails) and read the PostgreSQL log (`no suitable key share`); (2) the host's default client does NOT offer ML-DSA in `signature_algorithms` — Amazon Linux's crypto policy (`/etc/crypto-policies/back-ends/opensslcnf.config`, included from `openssl.cnf`) fixes a classical list — so Phase C needs `-sigalgs mldsa65` for s_client and a private `OPENSSL_CONF` for psql; (3) libpq's SCRAM channel binding cannot hash an ML-DSA-signed certificate (`could not find digest for NID UNDEF`) — add `channel_binding=disable`. All measured values are in Chapter 19. The steps below are retained as written, with the working commands in the "Measured" notes.

*Purpose: change one variable — the OpenSSL the database is linked against — and measure what it does to every TLS session the database terminates. The experiment was handed to us by the image maintainers (measured 2026-09-20, Runbook 04 Step 2): the official `postgres:17` image is PostgreSQL 17.11 on Debian 13 with OpenSSL 3.5.7, and its `17-bookworm` variant is the same 17.11 on Debian 12 with OpenSSL 3.0.20. Same database, same version, one tag apart, two libssl. Phase A measures the bookworm control with TLS on: the classical baseline as a handshake. Phase B switches TLS on in the Chapter 18 stack (already trixie) and measures again: the expected reading is `X25519MLKEM768` with no configuration. Phase C issues the database an ML-DSA-65 server certificate from our own CA and measures `psql` under `sslmode=verify-full` — and measures what EJBCA's Java 17 JDBC driver does when it meets that certificate, which is a result either way. Phase D restores whichever certificate the measurements say the stack should run on. Prerequisite: Runbook 04 complete (stack up, root re-initialized as `PQC-MLDSA87-CA`, `pqc-root-ch18.pem` on the host). No Fortanix or AWS credential is used. Instrument: `openssl s_client -starttls postgres`, which speaks PostgreSQL's SSLRequest natively; `pg_stat_ssl` confirms a session but does not show the key-exchange group, so s_client is the record. The prediction this runbook originally carried — Debian 12, OpenSSL 3.0, a rebuild required — was wrong and is retained in the Appendix as the route for readers whose image has not moved.*

## Step 0 — Client tools on the host, and the pins

```bash
sudo dnf -y install postgresql17            # psql; substitute the newest major `dnf list --available 'postgresql*'` offers
psql --version
ldd $(which psql) | grep -E 'ssl|crypto'    # expect libssl.so.3 → /usr/lib64 (the host's 3.5.7)
openssl version                              # OpenSSL 3.5.7 (Amazon Linux 2023)
cd ~/stack && docker compose ps
docker compose exec db openssl version       # OpenSSL 3.5.7 (trixie) — Runbook 04 Step 2
docker run --rm postgres:17-bookworm openssl version   # OpenSSL 3.0.20 — the control
```

Pins (both measured 2026-09-20): `postgres@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232` (17.11, Debian 13, OpenSSL 3.5.7); `postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652` (17-bookworm, 17.11, Debian 12, OpenSSL 3.0.20).

## Step 1 — One server certificate for both sides (ECDSA P-256, self-signed, 90 days; Phase C replaces it)

```bash
mkdir -p ~/stack/certs && cd ~/stack
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
  -subj "/CN=db/O=PQC Book Part3/C=US" -addext "subjectAltName=DNS:db,DNS:localhost,IP:127.0.0.1" \
  -keyout certs/server.key -out certs/server.crt
sudo chown 999:999 certs/server.key && sudo chmod 600 certs/server.key      # both official images run PostgreSQL as uid 999
openssl x509 -in certs/server.crt -noout -subject -ext subjectAltName
```

PostgreSQL refuses a private key readable by others or owned by neither root nor the server user. `certs/` is git-ignored.

## Phase A — the control: PostgreSQL 17.11 on Debian 12, OpenSSL 3.0.20 (Step 2)

Run the bookworm image standalone, on a throwaway volume and a second loopback port, so the stack is untouched:

```bash
docker run -d --rm --name pg-bookworm -e POSTGRES_PASSWORD=control -p 127.0.0.1:5433:5432 \
  -v ~/stack/certs:/certs:ro postgres:17-bookworm \
  -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key -c ssl_min_protocol_version=TLSv1.3
sleep 5; docker logs pg-bookworm 2>&1 | grep -i -E 'ready|ssl|fatal' | tail -3
openssl s_client -starttls postgres -connect 127.0.0.1:5433 -brief </dev/null 2>&1 | grep -E 'Protocol version|Ciphersuite|Signature type|Negotiated|Verification'
openssl s_client -starttls postgres -connect 127.0.0.1:5433 -brief -groups X25519MLKEM768 </dev/null 2>&1 | grep -E 'Negotiated|alert|error'; echo "exit=${PIPESTATUS[0]}"
docker stop pg-bookworm
```

Expected: the default offer completes; the hybrid-only offer fails with alert 40. *Measured 2026-09-20: TLSv1.3 / TLS_AES_256_GCM_SHA384 / ecdsa_secp256r1_sha256 on the default offer; `SSL alert number 40` on `-groups X25519MLKEM768`. On 17 this is ALSO the P-256-only policy of `ssl_ecdh_curve`, not only OpenSSL 3.0 — the library-only control is the same image with `-c ssl_ecdh_curve=X25519`, which 17 refuses at startup on either OpenSSL.* Save as `transcripts/ch19-phaseA-bookworm-control.txt`.

## Phase B — the stack: same 17.11 on Debian 13, OpenSSL 3.5.7 (Steps 3–4)

### 3. TLS on, EJBCA required to use it

```bash
cd ~/stack   # copy stack/docker-compose.tls.yml from the repo
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d
docker compose logs --tail 20 db | grep -i -E 'ssl|ready|fatal'
sleep 75; docker compose logs --tail 60 ejbca | grep -i -E 'datasource|postgres|ssl|handshake|started in'
dc() { docker compose -f ~/stack/docker-compose.yml -f ~/stack/docker-compose.tls.yml "$@"; }   # a function, not an alias: it must work inside $E below
```

### 4. THE MEASUREMENT: the other libssl

```bash
openssl s_client -starttls postgres -connect 127.0.0.1:5432 -brief </dev/null 2>&1 | grep -E 'Protocol version|Ciphersuite|Signature type|Negotiated|Verification'
openssl s_client -starttls postgres -connect 127.0.0.1:5432 -brief -groups X25519MLKEM768 </dev/null 2>&1 | grep -E 'Negotiated|alert|error'
psql "host=127.0.0.1 port=5432 dbname=ejbca user=ejbca sslmode=require" -c "select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid();"
# the third client: EJBCA's Java 17 JDBC driver, now on TLS against a hybrid-capable server
dc exec db psql -U ejbca -d ejbca -c "select pid, ssl, version, cipher, client_addr from pg_stat_ssl join pg_stat_activity using (pid) where usename='ejbca' and client_addr is not null;"
dc exec ejbca java -version 2>&1 | head -1
```

*Measured 2026-09-26 (on 18.6 after the migration; see the box at the top): `-groups X25519MLKEM768` alone → `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384`; standalone 18 accepted hybrid, X25519 and secp256r1 as single offers; 17 on the same OpenSSL refused all but P-256. EJBCA (OpenJDK 17.0.16) reconnected with ten sessions `t | TLSv1.3 | TLS_AES_256_GCM_SHA384` and the log showed zero `no suitable key share` after the cutover → Java offered a listed classical group.* Migration: `docker compose exec -T db pg_dump -U ejbca -Fc ejbca > ejbca-17-<ts>.dump`; `docker compose stop ejbca db`; scp the updated compose files; `dc up -d db`; `docker compose exec -T db pg_restore -U ejbca -d ejbca --no-owner < ejbca-17-*.dump`; `dc up -d ejbca`. Save as `transcripts/ch19-phaseB-pg18.txt`.

## Phase C — the database's own certificate from our CA, ML-DSA-65 (Steps 5–7)

### 5. Key, CSR, issuance — the Section 17.7 flow, aimed at the database

```bash
cd ~/stack
openssl genpkey -algorithm ML-DSA-65 -out db-mldsa65.key
openssl req -new -key db-mldsa65.key -subj "/CN=db/O=PQC Book Part3/C=US" \
  -addext "subjectAltName=DNS:db,DNS:localhost,IP:127.0.0.1" -out db-mldsa65.csr
dc cp db-mldsa65.csr ejbca:/tmp/db-mldsa65.csr
E="dc exec ejbca /opt/keyfactor/ejbca/bin/ejbca.sh"
$E ra addendentity --username pqc-db --password '<pw>' \
   --dn "CN=db,O=PQC Book Part3,C=US" --altname "dNSName=db,dNSName=localhost,iPAddress=127.0.0.1" \
   --caname PQC-MLDSA87-CA --type 1 --token USERGENERATED --certprofile SERVER --eeprofile EMPTY
$E createcert --username pqc-db --password '<pw>' -c /tmp/db-mldsa65.csr -f /tmp/db-mldsa65.pem
dc cp ejbca:/tmp/db-mldsa65.pem ./db-mldsa65.pem
openssl x509 -in db-mldsa65.pem -noout -text | grep -E 'Signature Algorithm|Public Key Algorithm|DNS:|IP Address' | sort -u
openssl verify -CAfile pqc-root-ch18.pem db-mldsa65.pem            # db-mldsa65.pem: OK
```

The `--altname` carries `db` (EJBCA's name for the host on the Compose network) and `localhost`/`127.0.0.1` (psql's, from the host); `verify-full` checks the name.

### 6. Swap the certificate — a file change and a restart, not a re-init

```bash
cp certs/server.crt certs/server.crt.ecdsa; sudo cp certs/server.key certs/server.key.ecdsa      # Phase D needs these back
sudo cp db-mldsa65.key certs/server.key && sudo chown 999:999 certs/server.key && sudo chmod 600 certs/server.key
cp db-mldsa65.pem certs/server.crt
dc restart db
dc logs --tail 10 db | grep -i -E 'ssl|error|fatal|ready'
```

If PostgreSQL logs an error loading the key or certificate, capture the exact line — a server-side refusal of an ML-DSA key would itself be a finding of the Gate B tooling class.

### 7. THE MEASUREMENT: a fully post-quantum-authenticated database session — and what Java 17 does with it

```bash
openssl s_client -starttls postgres -connect 127.0.0.1:5432 -brief -CAfile pqc-root-ch18.pem -verify_return_error </dev/null 2>&1 \
  | grep -E 'Protocol version|Ciphersuite|Signature type|Negotiated|Verification'
psql "host=localhost port=5432 dbname=ejbca user=ejbca sslmode=verify-full sslrootcert=$PWD/pqc-root-ch18.pem" \
  -c "select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid();"
# now the third client: EJBCA restarted against a database whose certificate is ML-DSA-65
dc restart ejbca
sleep 75; dc logs --tail 80 ejbca | grep -i -E 'datasource|postgres|ssl|handshake|exception|started in' | head -20
```

*Measured 2026-09-26: the commands above FAIL as written — server log `no suitable signature algorithm` for every client, including OpenSSL 3.5.7 — because Amazon Linux's crypto policy withholds ML-DSA from the client's `signature_algorithms`. Working forms:*

```bash
openssl s_client -starttls postgres -connect 127.0.0.1:5432 -CAfile pqc-root-ch18.pem -sigalgs mldsa65:mldsa87:ecdsa_secp256r1_sha256 -groups X25519MLKEM768 </dev/null 2>&1 | grep -i -E 'Peer signature type|Cipher is|Verify return'
#   → Peer signature type: mldsa65 / New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384 / Verify return code: 0 (ok)
cat > ~/stack/openssl-pqc.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = sys_sect
[sys_sect]
SignatureAlgorithms = mldsa65:mldsa87:mldsa44:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256
Groups = X25519MLKEM768:X25519:prime256v1
EOF
PGPASSWORD=$(grep '^DB_PASSWORD=' ~/stack/.env | cut -d= -f2-) OPENSSL_CONF=~/stack/openssl-pqc.cnf \
  psql "host=localhost port=5432 dbname=ejbca user=ejbca sslmode=verify-full sslrootcert=$PWD/pqc-root-ch18.pem channel_binding=disable" \
  -c "select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid();"
#   → t | TLSv1.3 | TLS_AES_256_GCM_SHA384   (without channel_binding=disable: "could not find digest for NID UNDEF")
```

Expected, host side: `Peer signature type: mldsa65`, `Verify return code: 0 (ok)`, and `psql` connecting under `verify-full` with the ML-DSA-87 root as its only trust anchor — key exchange, server authentication, and the chain above it all post-quantum, no classical algorithm anywhere in the session. Expected, EJBCA side: a handshake failure in the log — Java 17's TLS stack neither offers nor understands the ML-DSA signature schemes, so the server has nothing in common with the client and aborts. That failure is a measurement, not a defect in the runbook: the JDK-17 wall (finding #73) for the third time; the chapter's sentence is that the same database serves a post-quantum session to `psql` and no session at all to the CA, on the same evening, with the same certificate. If EJBCA connects instead, that is a better finding — capture `java -version` and `pg_stat_ssl` — and Phase D changes accordingly. *Measured 2026-09-26: 33 × `javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure` → `Unable to acquire JDBC Connection` → CLI cannot instantiate; OpenJDK 17.0.16.* Save as `transcripts/ch19-phaseC-mldsa65.txt`.

## Phase D — decide what the stack runs on (Step 8)

```bash
# if Step 7 showed EJBCA cannot connect (expected): restore the ECDSA certificate so the CA is operable; keep the ML-DSA pair for the chapter
sudo cp certs/server.key.ecdsa certs/server.key && sudo chown 999:999 certs/server.key && sudo chmod 600 certs/server.key
cp certs/server.crt.ecdsa certs/server.crt
dc restart db ejbca
sleep 75; $E ca listcas
openssl s_client -starttls postgres -connect 127.0.0.1:5432 -brief </dev/null 2>&1 | grep -E 'Signature type|Negotiated'   # ecdsa_secp256r1_sha256 + X25519MLKEM768
```

The resulting posture is the honest one for a Java-17 CA: post-quantum key exchange on every database session whose client offers it, classical server authentication until the CA's own runtime can verify ML-DSA. Chapter 20's ceremony does not depend on which certificate the database wears. *Measured 2026-09-26: both CAs back; `Peer signature type: ecdsa_secp256r1_sha256` over `-groups X25519MLKEM768`; 10 TLS sessions in `pg_stat_ssl`.*

## Step 9 — Hygiene

```bash
history -c
```

Stop the instance from the workstation when finished. The only credential typed tonight was the EJBCA end-entity password in Step 5 and the `psql` prompts, none of which `history` keeps once cleared.

## Deliverables to the repo

`transcripts/ch19-phaseA-bookworm-control.txt`, `ch19-phaseB-trixie.txt`, `ch19-phaseC-mldsa65.txt`; `transcripts/db-mldsa65.pem` (the certificate, never the key); both PostgreSQL digests in the pins table; the Phase D decision as one line in the chapter. The dump files and everything under `certs*/` stay on the host.

## Appendix — Route B: when the image has not moved (Amazon Linux 2023 base)

Kept for readers whose PostgreSQL image is still linked against an OpenSSL without ML-KEM (any Debian 12-based image, most images older than mid-2025). `stack/postgres-al2023/` builds PostgreSQL 17 from the Amazon Linux 2023 package set, which links the OpenSSL AL2023 ships (3.5.7 at the time of writing): `docker build --build-arg PG_MAJOR=17 -t pqc-postgres:17-al2023 stack/postgres-al2023`; `docker run --rm pqc-postgres:17-al2023 sh -c 'postgres --version; openssl version; id postgres'` (expect uid 26 — the key's owner for `certs-al2023/`). The AL2023 package keeps its data at `/var/lib/pgsql/data`, so the stock volume is not reusable: dump from the running stack (`docker compose exec -T db pg_dump -U ejbca -Fc ejbca > ejbca.dump`), bring the database up with `docker-compose.pqc.yml`, restore (`docker compose exec -T db pg_restore -U ejbca -d ejbca --no-owner < ejbca.dump`), then run Steps 4–8 unchanged. The dump plus `.env` is the CA (Section 18.3); handle it so.
