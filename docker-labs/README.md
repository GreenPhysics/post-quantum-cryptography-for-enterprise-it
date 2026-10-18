# PQC Lab Companion — Docker

The book keeps one rule: **no claim without its experiment.** This container
externalizes the book's experiments: it runs every self-contained lab on
*your* hardware at startup and serves the transcripts as a web page, so you
can verify the book's results for yourself without building any
infrastructure.

## Quick start (prebuilt image)

```bash
docker run -p 8080:8080 ghcr.io/OWNER/REPO:latest
# then open http://localhost:8080
```

## Build it yourself

```bash
git clone https://github.com/OWNER/REPO
cd REPO/docker-labs
docker compose up --build
# then open http://localhost:8080
```

The image compiles the exact OpenSSL version the book pins (see
`ARG OPENSSL_VERSION` in the Dockerfile), so your transcripts show native
ML-DSA and ML-KEM regardless of what your operating system ships.

## What runs

At container start, five self-contained labs execute once (about a minute
total): TLS session reuse, certificate revocation (CA side), CRL checking
(client side), OCSP stapling, and TLS renegotiation. The page shows each
lab's PASS/FAIL verdicts, duration, and full transcript — including the
probes that fail on purpose, because the failures are where the learning is.

Two interactive tools ship in the container for your own targets:

```bash
docker exec -it <container> /opt/pqc/labs/audit-cnsa2.sh endpoint host:port
docker exec -it <container> /opt/pqc/labs/build-tomcat-stores.sh /tmp/stores
```

## Layout

```
docker-labs/
├── Dockerfile                        # multi-stage; builds pinned OpenSSL
├── docker-compose.yml                # build context = repo root
├── entrypoint.sh                     # run labs → make report → serve
├── run-labs.sh                       # executes labs, captures transcripts
├── make-report.py                    # builds the single-file report page
└── github-workflow-build-image.yml   # copy to .github/workflows/
```

Lab methodology derives from the MIT-licensed
[f5devcentral/openssl-pqc-stepbystep-lab](https://github.com/f5devcentral/openssl-pqc-stepbystep-lab);
see LICENSE/NOTICE.
