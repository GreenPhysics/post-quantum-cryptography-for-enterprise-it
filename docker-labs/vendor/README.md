# vendor/ — pinned build inputs

The PQC Tomcat image builds from pinned tarballs rather than distribution
packages. Two reasons: Red Hat UBI 9 carries no JDK new enough for the Foreign
Function & Memory API that Tomcat's OpenSSL connector requires, and pinning
makes the image reproducible — a reader building it next year gets the same
components the book describes.

Place these three files here before building.

| File | What | Where to get it |
|---|---|---|
| `openssl-3.5.7.tar.gz` | OpenSSL source, 3.5.0 or later | openssl.org / GitHub releases |
| `jdk-x64.tar.gz` | JDK **24+**, Linux **x64** — the RHEL production target | adoptium.net (Temurin) |
| `jdk-aarch64.tar.gz` | JDK **24+**, Linux **aarch64** — for arm64 build hosts | adoptium.net (Temurin) |
| `apache-tomcat-11.0.24.tar.gz` | Tomcat 11 | tomcat.apache.org (architecture-independent) |

Notes:

- **Both JDK architectures are listed deliberately.** Enterprise Red Hat is
  predominantly x86_64, which is the deployment target; but build hosts are
  frequently Apple Silicon or arm64 CI runners. The Dockerfile selects by
  `TARGETARCH`, so a multi-architecture build (`docker buildx build --platform
  linux/amd64,linux/arm64`) produces an image usable on both. If you only ever
  build for one, supply just that tarball — the other is not extracted.
  Rename the download to exactly `jdk-x64.tar.gz` or `jdk-aarch64.tar.gz`.
- Building an x86_64 image on Apple Silicon works via QEMU emulation
  (`--platform linux/amd64`) but is noticeably slower; iterating natively and
  letting CI publish both architectures is usually the faster loop.
- The OpenSSL and Tomcat archives are source and bytecode respectively, so they
  are architecture-independent.
- **JDK 24 is the floor.** The FFM API is what lets Tomcat call `libssl`
  directly. Earlier JDKs cannot run this connector, and no JDK — including 26 —
  supplies post-quantum TLS through JSSE, which is precisely why TLS here runs
  on OpenSSL instead.
- The exact filenames above are what the Dockerfile expects; adjust the
  `ARG` values at the top of `Dockerfile.tomcat` if your versions differ.

These files are deliberately **not** committed to the repository: they are
large, and their licenses are their vendors' to distribute. The GitHub Action
that publishes the image fetches them at build time.
