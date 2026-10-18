# Required Linux Installs

*This list is publishable book content (feeds the Lab Setup appendix) and ships
with the labs. It is extracted from the working Dockerfile and validated lab
runs, not assembled from memory. Package names are Debian/Ubuntu (`apt`);
RHEL/Fedora equivalents are noted where they differ.*

## 1. To run the labs directly on a host

| Requirement | Debian/Ubuntu package | Purpose |
|---|---|---|
| bash 4+ | `bash` (preinstalled) | All lab scripts |
| OpenSSL **3.5.0+** | build from source (§3) or distro ≥ Debian 13 | Every cryptographic operation; ML-KEM/ML-DSA/SLH-DSA require 3.5+ |
| GNU coreutils | `coreutils` (preinstalled) | `mktemp`, `date`, `stat`, checksums |
| procps | `procps` | `pkill -x` in lab cleanup traps |
| grep/sed/awk | `grep`, `sed`, `gawk` or `mawk` (preinstalled) | Transcript assertions |
| timeout | part of `coreutils` | Bounded network probes |

Pre-3.5 OpenSSL is tolerated: every lab auto-detects and falls back to
classical algorithms with a loud notice — mechanics identical, PQC
signatures absent.

## 2. Additional, per component

| Component | Requirement | Package / source |
|---|---|---|
| Report page generator | Python 3.8+ (stdlib only) | `python3` |
| Report web server | Python 3 http.server | `python3` (same) |
| Tomcat keystore lab — full JKS path | JDK **24+** (ML-DSA) | Temurin/OpenJDK tarball; `keytool` on PATH |
| Tomcat keystore lab — SLH-DSA stores | Bouncy Castle provider | `bcprov`/`bctls` JARs registered in `java.security` |
| Tomcat deployment target | Apache Tomcat 10.1/11 | tarball from tomcat.apache.org |
| Container build | Docker Engine + Compose v2 | `docker.io` + `docker-compose-plugin` (or Docker Desktop) |

## 3. To build OpenSSL 3.5.x from source

Validated in the container build (Dockerfile stage 1):

```
apt-get install -y build-essential perl curl ca-certificates
```

(RHEL/Fedora: `dnf install gcc make perl curl ca-certificates`.)

```bash
curl -fsSL -o openssl.tar.gz \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
tar xzf openssl.tar.gz && cd openssl-3.5.0
./Configure --prefix=/opt/openssl --libdir=lib no-docs
make -j"$(nproc)" && sudo make install_sw install_ssldirs
# install_ssldirs is required: it installs the default openssl.cnf.
# Without it, `openssl req` fails with "Can't open .../openssl.cnf".
```

**Where the files land.** OpenSSL uses two independent paths, and confusing them
wastes time (verified on macOS 26 with a plain `perl Configure`, no arguments):

| Path | Set by | Contents |
|---|---|---|
| `/usr/local/bin`, `/usr/local/lib`, `/usr/local/include` | `--prefix` (default `/usr/local`) | `openssl` binary, `libssl.3.dylib`/`libcrypto.3.dylib`, headers |
| `/usr/local/ssl` | `--openssldir` (default) | `openssl.cnf`, `certs/`, `private/` |

So the binary is **not** under `--openssldir`. Library path for applications that
link OpenSSL (e.g. Tomcat's OpenSSL connector) is the `--prefix` `lib` directory.
Also note `make install_sw` alone installs binaries and libraries but not the
config directory; `install_ssldirs` does the latter, and a partial install leaves
`/usr/local/ssl` populated with no binary in sight.

**PATH order matters.** On a machine with a packaged OpenSSL, plain `openssl`
may resolve to that build rather than the one just installed. Verify explicitly:

```bash
/usr/local/bin/openssl version                                   # the source build
/usr/local/bin/openssl list -tls-groups | grep -i mlkem          # ML-KEM groups present?
/usr/local/bin/openssl list -signature-algorithms | grep -c ML-DSA
export PATH=/opt/openssl/bin:$PATH LD_LIBRARY_PATH=/opt/openssl/lib
openssl version    # → OpenSSL 3.5.0
```

## 4. Container route (no host installs beyond Docker)

The Lab Companion container carries everything in §1–§3 internally; the
reader installs only Docker:

```bash
docker run -p 8080:8080 ghcr.io/OWNER/REPO:latest   # → http://localhost:8080
```

## 5. Explicitly NOT required

No quantum hardware, no liboqs, no oqs-provider (OpenSSL 3.5+ is native),
no external Python packages, no Node.js, no database. The CNSA 2.0 lab
series' liboqs/oqs-provider build instructions are superseded by native
3.5 — see the CNSA 2.0 chapter's translation table.
