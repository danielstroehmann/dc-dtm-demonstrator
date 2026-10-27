# Minion: one simulated device running DigiCert TrustEdge. Built on the target system from DigiCert's public
# release (pinned version and checksums) – the demonstrator does not redistribute TrustEdge.
FROM debian:13-slim
ARG TARGETARCH
ARG TRUSTEDGE=26.6.3-567
ARG SHA256_amd64=d0112245c167e5e760fdbbcd1ba81bc8d8a003202177a9dc407aa9cc16549785
ARG SHA256_arm64=cfb0ee5860d27685b1470d359f8fd392d4cdf1a97efce7c8dbcc6c3e089d2746
RUN set -eu; \
    apt-get update; apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    case "$TARGETARCH" in amd64) arch=x64 sum=$SHA256_amd64 ;; arm64) arch=aarch64 sum=$SHA256_arm64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; esac; \
    curl -fsSL -o /tmp/te.zip "https://github.com/digicert/trustedge/releases/download/trustedge_$TRUSTEDGE/trustedge-$arch-deb.zip"; \
    echo "$sum  /tmp/te.zip" | sha256sum -c -; \
    unzip -q /tmp/te.zip -d /tmp/te; \
    DIGICERT_EULA_ACCEPT=yes dpkg -i /tmp/te/*.deb; \
    rm -rf /tmp/te /tmp/te.zip /var/lib/apt/lists/*
# Factory firmware v1 – OTA updates (DTM artifacts run by the agent) replace it; the agent's user may write it
RUN mkdir -p /opt/firmware && echo 1 > /opt/firmware/version.txt && chown -R trustedge:trustedge /opt/firmware
COPY --chmod=0755 entrypoint.sh /usr/local/bin/minion
ENTRYPOINT ["/usr/local/bin/minion"]
