# Part III — Runbook 04: The CA stack on PostgreSQL (Docker Compose, named volumes, restart policy)

*Purpose: replace the Chapter 17 dry run — one `docker run`, H2 on an anonymous volume, no restart policy — with a declared stack: EJBCA Community by digest, PostgreSQL 17 by digest, two named volumes, `restart: unless-stopped`, secrets in a git-ignored `.env`. Every step is transcribed for Chapter 18; the probe outputs fill Section 18.6 and 18.8. Nothing here needs Fortanix or AWS credentials. Executed on the Part III EC2 host (`ssh -i ~/.ssh/pqc-lab ec2-user@<ca-host-eip>`). The dry-run container is stopped, not removed, until the new CA is issuing (Step 8).*

## Step 0 — Evidence before change (the Section 18.2 transcript)

Capture the dry run's state before touching it. This is the "before" picture of the chapter.

```bash
docker ps -a --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}' | head -5
docker inspect -f '{{json .HostConfig.RestartPolicy}}' ejbca          # expect {"Name":"no","MaximumRetryCount":0}
docker inspect -f '{{json .Mounts}}' ejbca | jq .                       # the anonymous volume on /mnt/persistent
docker volume ls
sudo ls -la /var/lib/docker/volumes/$(docker inspect -f '{{(index .Mounts 0).Name}}' ejbca)/_data
docker inspect -f '{{json .Config.Env}}' ejbca | jq -r '.[]' | grep -E 'DATABASE|PERSIST'   # the image's baked-in defaults: H2 at /mnt/persistent/ejbcadb, DATABASE_USER=ejbca, DATABASE_PASSWORD=ejbca
```

Expected: restart policy `no`; one anonymous 64-hex-named volume mounted at `/mnt/persistent`; inside it an `ejbcadb.mv.db` (the file-backed H2 database that carried the ML-DSA-87 dry-run root across the reboot). Save the output as `transcripts/ch18-step0-dry-run-state.txt`. *Measured 2026-09-20: `Exited (143)` = SIGTERM, the graceful stop H2 needed; `ejbcadb.mv.db` 397,312 bytes dated after the dry run's issuance; and the image's environment carries `DATABASE_PASSWORD=ejbca` as a default — the dry run had a database password, the vendor's, the same in every copy of the image.*

## Step 1 — Docker Compose on Amazon Linux 2023 (it is not in the repositories)

AL2023's `docker` package ships the engine without the Compose plugin. Install the plugin from Docker's release page and verify its checksum — the same discipline Chapter 17 applied to Terraform.

```bash
sudo dnf -y install jq
V=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name); echo "compose $V"
curl -fsSLO https://github.com/docker/compose/releases/download/$V/docker-compose-linux-x86_64
curl -fsSLO https://github.com/docker/compose/releases/download/$V/checksums.txt
grep ' \*docker-compose-linux-x86_64$' checksums.txt | sha256sum -c -          # expect: docker-compose-linux-x86_64: OK  (the file marks binaries with '*')
# verified live 2026-09-20: compose v5.5.1, sha256 db1889184726840f75c4f9c001048430d4f25b3be3cb084d3ddd762bc0aed576
sudo install -d /usr/local/lib/docker/cli-plugins
sudo install -m 0755 docker-compose-linux-x86_64 /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version                                                          # record for the chapter
```

If the API rate-limits the version lookup, read the version from https://github.com/docker/compose/releases and set `V` by hand. Record the version in `docker-labs/vendor/EJBCA-VERSIONS.md` beside the image pins (a short "Stack pins" table: EJBCA digest, PostgreSQL digest, Compose version).

## Step 2 — Pull PostgreSQL and pin it

```bash
docker pull postgres:17
docker inspect --format '{{index .RepoDigests 0}}' postgres:17            # postgres@sha256:...
docker run --rm postgres:17 postgres --version                            # e.g. postgres (PostgreSQL) 17.x
docker run --rm postgres:17 openssl version                               # which libssl the container's TLS is decided by (see the live result below)
docker run --rm postgres:17 sh -c 'ldd /usr/lib/postgresql/17/bin/postgres | grep -E "ssl|crypto"'
```

Put the digest into `stack/docker-compose.yml` in place of `postgres:17` (the file says where), and into the pins table. The `openssl version` line is the chapter's baseline for Chapter 19: the container's TLS is decided by the libssl inside it, not the host's.

**Measured live 2026-09-20:** `postgres@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232`, `PostgreSQL 17.11 (Debian 17.11-1.pgdg13+2)` — Debian **13 (trixie)** — `OpenSSL 3.5.7 9 Jun 2026`. The runbook's expectation of Debian 12 / OpenSSL 3.0 was wrong: the official image moved to trixie, which ships 3.5. The `17-bookworm` variant of the same 17.11 still carries `OpenSSL 3.0.20`, which makes the pair the controlled experiment of Runbook 05. Record both digests.

## Step 3 — Stack files and secrets

```bash
mkdir -p ~/stack
# From a PowerShell window on the WORKSTATION (the files live in the repo, not on the host yet):
#   cd "<repo>\labs\part3-aws\stack"
#   scp -i ~/.ssh/pqc-lab docker-compose.yml docker-compose.tls.yml .env.example ec2-user@<ca-host-eip>:stack/
# then, back on the host:
cd ~/stack && ls -la
cp .env.example .env && chmod 600 .env
for k in DB_PASSWORD PASSWORD_ENCRYPTION_KEY CA_KEYSTOREPASS; do sed -i "s|^$k=.*|$k=$(openssl rand -base64 24)|" .env; done
grep -c '=..' .env                                                       # expect 3 (values present; never print them)
docker compose config --quiet && echo "compose file OK"
```

`.env` is the custody of the issuing CA's key at rest (Chapter 18, Section 18.3). Copy it once to the workstation's password manager, then leave it on the host with mode 600; it must never enter the repository or a transcript.

## Step 4 — Stop the dry run (keep it) and bring the stack up

```bash
docker stop ejbca                                   # frees ports 80/443; the container and its volume stay for Step 8
cd ~/stack && docker compose up -d
docker compose ps                                   # db: healthy, ejbca: running
docker compose logs -f ejbca                        # Ctrl-C after "WildFly ... started in NNNN ms"; note the number for the chapter
```

Watch for the database lines in the EJBCA log: the driver it chose (`postgresql`), the schema creation, and the absence of the H2 warning that the dry run printed. Save the bring-up log as `transcripts/ch18-step4-compose-up.log` (it contains no secrets; confirm with `grep -c -i password`).

## Step 5 — Prove the database is the database

```bash
docker compose exec db psql -U ejbca -d ejbca -c '\dt' | head -40
docker compose exec db psql -U ejbca -d ejbca -c "select count(*) as tables from information_schema.tables where table_schema='public';"
docker compose exec db psql -U ejbca -d ejbca -c "select tokenname from cryptotokendata;"          # the bootstrap ManagementCA's token
docker compose exec db psql -U ejbca -d ejbca -c "select name, subjectdn from cadata;"
```

Expected: the EJBCA schema and the container's bootstrap `ManagementCA`. The `cryptotokendata` row is the sentence the chapter needs: the CA's private-key material now lives in PostgreSQL, protected by `CA_KEYSTOREPASS`.

*Measured 2026-09-20: `start.sh` logged `PostgreSQL database.`, `SELECT 1 -> hit`, probed `globalconfigurationdata` (the `does not exist` ERROR is the probe finding a fresh database, not a fault), then `Creating database tables...` from `create-tables-ejbca-postgres.sql` (479 lines); database healthy in 11.0 s; WildFly `started in 42825ms` (dry run on H2: 43,182 ms — the database is invisible in application start); **37 tables**; `cryptotokendata` = `ManagementCA`; `cadata` = one row; `grep -c -i password` on the log = 6, all `start.sh` narrating where it looked for keystore files, no values — and the first of them, `Setting the password.encryption.key.`, is the image confirming it took `PASSWORD_ENCRYPTION_KEY` from `.env`.*

## Step 6 — Re-issue the post-quantum CA on the new stack (clean re-init, per Section 18.7)

The dry-run root was disposable and its construction is transcribed in Chapter 17 Section 17.6; rebuild rather than migrate. Same commands, new container name:

```bash
cd ~/stack                                   # every host block starts here: a dropped SSH session lands in ~ and Compose finds no file
read -s -p "token PIN (generate with openssl rand -base64 18; record it with the .env values NOW): " PIN; echo
E="docker compose exec ejbca /opt/keyfactor/ejbca/bin/ejbca.sh"
$E ca init \
  --caname "PQC-MLDSA87-CA" \
  --dn "CN=PQC MLDSA87 Root CA,O=PQC Book Part3,C=US" \
  --tokenType soft --tokenPass "$PIN" \
  --keytype ML-DSA-87 --keyspec ML-DSA-87 \
  -v 3650 --policy null -s ML-DSA-87
$E ca listcas
$E ca getcacert --caname PQC-MLDSA87-CA -f /tmp/pqc-root.pem
docker compose cp ejbca:/tmp/pqc-root.pem ./pqc-root-ch18.pem
openssl x509 -in pqc-root-ch18.pem -noout -text | grep -E 'Signature Algorithm|Public Key Algorithm' | sort -u
docker compose exec db psql -U ejbca -d ejbca -c "select name, subjectdn from cadata;"      # now two rows: ManagementCA and the PQC root
unset PIN
```

*Measured 2026-09-20: `Creating CA...` 01:51:36,340 → `CA initialized` 01:51:36,948 = **607 ms** on PostgreSQL against 412 ms on H2 — the write path is visible, the key generation is not; `CAId -583139359`, the same as the dry run's (EJBCA derives it from the subject DN, so a CA rebuilt from its transcript is reproducible down to its identifier); `cadata` two rows; OpenSSL reads `Public Key Algorithm: ML-DSA-87` / `Signature Algorithm: ML-DSA-87`. PIN lesson, learned the hard way: the placeholder `'<pin>'` was passed literally, and five later attempts to change it with `cryptotoken setpin` (which needs `--oldpin`/`--newpin` on the command line — the container CLI has no console for prompting) all failed with `PKCS12 key store mac invalid`. The token stays `active, auto` because EJBCA holds the activation PIN itself, so the CA is operable but its PIN is not manageable. Hence the `read -s` above: the token PIN is the fourth piece of the issuing key's custody and is recorded with the three `.env` values at creation.*

The `ca init` line is Chapter 17 Section 17.6's, unchanged, with `docker exec ejbca` replaced by the Compose form. The `Creating CA...` to `CA initialized` timestamps in its output are the chapter's second datum against the dry run's 412 ms on H2: the database changed, the key generation did not, and the number will say whether the write path did. The leaf issuance (Section 17.7: `ra addendentity --token USERGENERATED`, `createcert`) is not repeated here; Chapter 20's issuing CA replaces this root as the signer of leaves.

## Step 7 — The two survival tests (Section 18.8)

```bash
# 7a: stack restart — the CA must come back from PostgreSQL, not from the container
docker compose down && docker compose up -d && sleep 90
$E ca listcas                                                              # the ML-DSA-87 CA is still there
docker volume ls | grep pqc-ca                                             # pqc-ca_pgdata, pqc-ca_ejbca-persistent

# 7b: host reboot — the restart policy must bring both containers back unattended
sudo reboot
# ... reconnect after ~60 s ...
docker compose -f ~/stack/docker-compose.yml ps                            # both Up without any docker start
docker ps -a --format 'table {{.Names}}\t{{.Status}}'                       # the old dry-run 'ejbca' stays Exited — the control
$E ca listcas
```

The dry-run container is the control for 7b: same host, same reboot, no restart policy, and it stays down. That contrast is Figure 18-1.

*7a measured 2026-09-20, twice: containers and network removed, recreated; db healthy in 10.9 s; both CAs listed from PostgreSQL; volumes `pqc-ca_pgdata` and `pqc-ca_ejbca-persistent` intact. An SSH disconnect during the session was the session, not the host (`uptime` continuous since before Step 4).*

*7b measured 2026-09-20: after `sudo reboot`, `uptime` 11 min; `pqc-ca-ejbca-1` Up 11 minutes, `pqc-ca-db-1` Up 11 minutes (healthy), `ejbca` (dry run) Exited (143) 11 days ago — three containers, two states, on the same host through the same reboot; `ca listcas` returned both CAs. Figure 18-1.*

## Step 8 — Retire the dry run (only after Step 7 passes)

```bash
docker rm -v ejbca                                                          # -v removes the anonymous volume with it
docker volume ls                                                            # only the two named pqc-ca volumes remain
```

*Done 2026-09-20: `docker rm -v ejbca`; `docker volume ls` → `pqc-ca_ejbca-persistent`, `pqc-ca_pgdata` only.*

## Step 9 — Hygiene and stop

```bash
history -c
```

Stop the instance from the workstation when finished. The named volumes persist on the EBS root volume; the stack returns on the next boot without intervention — which is the whole point of the runbook, and Step 7b already proved it.

## Deliverables to the repo

`transcripts/ch18-step0-dry-run-state.txt`, `transcripts/ch18-step4-compose-up.log`, `transcripts/ch18-step5-schema.txt`, `transcripts/ch18-step7-survival.txt`, `transcripts/pqc-root-ch18.pem`; the pins table entry in `EJBCA-VERSIONS.md`; the compose file with the PostgreSQL digest filled in. Figure 18-1 from Step 7b.
