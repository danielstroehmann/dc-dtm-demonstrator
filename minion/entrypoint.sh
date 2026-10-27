#!/bin/sh
# A minion's life in the field: bootstrap certificate via EST with the factory's one-time passcode (CN = serial
# number) → bootstrap configuration via mTLS → TrustEdge agent, which fetches and renews the operational
# certificate itself. A restarted container skips what is already done (state in /etc/digicert).
set -eu
: "${DTM_HOST:?}" "${SERIAL:?}" "${BOOT_POLICY:?}" "${GROUP_ID:?}"
KS=/etc/digicert/keystore
log() { printf '{"minion":"%s","event":"%s"}\n' "$SERIAL" "$1"; }

# The agent's local API binds to "localhost" – Docker's ::1 entry makes it fail (verified)
sed '/^::1/d' /etc/hosts > /tmp/hosts && cat /tmp/hosts > /etc/hosts
rm -f /run/trustedge.pid  # left by a stopped container

if [ ! -s "$KS/certs/bootstrap.pem" ]; then
  : "${PASSCODE:?}"
  # TrustEdge trusts only its own keystore for TLS – the DTM host's public root
  cp /etc/ssl/certs/DigiCert_Global_Root_G2.pem "$KS/ca/"
  printf 'commonName=%s\n' "$SERIAL" > "$KS/conf/bootstrap.cnf"
  log bootstrap_enrolling
  # DTM's passcode auth needs some username next to the passcode with TrustEdge (verified). -noverify only skips
  # checking the issued certificate against the keystore – TLS to DTM is still verified (root above).
  trustedge certificate est --algorithm ECC --curve P256 --csr-conf bootstrap.cnf --key-alias bootstrap \
    --uri "https://$DTM_HOST/.well-known/est/devicetrustmanager/$BOOT_POLICY/device-group/$GROUP_ID/simpleenroll" \
    -authscheme BASIC -user device -pass "$PASSCODE" -noverify
  [ -s "$KS/certs/bootstrap.pem" ] || { log bootstrap_failed; exit 1; }
  log bootstrap_enrolled
fi
unset PASSCODE  # one-time – used up now

if [ ! -s /etc/digicert/conf/bootstrap_config.json ]; then
  # Right after the bootstrap enrollment DTM may still answer 400 – retry for a while (seen on US)
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    trustedge agent --download --devtm-bootstrap-uri "https://clientauth.$DTM_HOST/devicetrustmanager/api/v4/bootstrap-config/download" \
      --bootstrap-zip /tmp/bootstrap.zip --bootstrap-key "$KS/keys/bootstrap.pem" --bootstrap-cert "$KS/certs/bootstrap.pem" \
      && break
    [ "$attempt" = 10 ] && { log configuration_failed; exit 1; }
    sleep 3
  done
  trustedge agent --configure --bootstrap-zip /tmp/bootstrap.zip --bootstrap-key "$KS/keys/bootstrap.pem" \
    --trustedge-user trustedge --trustedge-group trustedge
  rm -f /tmp/bootstrap.zip
  log configured
fi

# Set at every start. DTM hands a device its pending deployments and policy changes only when the agent connects
# (verified on US: a deployment created while the agent stayed connected arrived only after a reconnect). So the
# agent reconnects as often as TrustEdge allows instead of staying connected: online for UPTIME_S (default 25 s;
# TrustEdge ships 5 minutes), then SLEEP_S offline (default 5 s; ships 1 hour) – every change reaches the device
# within about half a minute. The agent renews once less than RENEWAL_HOURS of a certificate are left.
sed -i -E "0,/\"connection_uptime_interval\": [0-9]+/s//\"connection_uptime_interval\": ${UPTIME_S:-25}/; \
  0,/\"sleep_interval\": [0-9]+/s//\"sleep_interval\": ${SLEEP_S:-5}/; \
  0,/\"keepalive_interval\": [0-9]+/s//\"keepalive_interval\": ${KEEPALIVE_S:-30}/; \
  0,/\"renewal_hours\": [0-9]+/s//\"renewal_hours\": ${RENEWAL_HOURS:-12}/; s/\"loglevel\": \"[A-Z]+\"/\"loglevel\": \"INFO\"/" \
  /etc/digicert/trustedge.json
log agent_starting
# The agent runs as a child: this shell reports the installed firmware (changed by OTA updates) to the container log –
# on every change and once a minute, so it stays within the log tail the demonstrator reads
trustedge --daemon &
agent=$!
trap 'kill "$agent" 2>/dev/null' TERM INT
seen='' tick=0
while kill -0 "$agent" 2>/dev/null; do
  version=$(cat /opt/firmware/version.txt 2>/dev/null || echo 0)
  case "$version" in ''|*[!0-9]*) version=0 ;; esac
  if [ "$version" != "$seen" ] || [ "$tick" -ge 30 ]; then
    printf '{"minion":"%s","event":"firmware","version":%s}\n' "$SERIAL" "$version"
    seen=$version tick=0
  fi
  tick=$((tick + 1))
  sleep 2
done
wait "$agent"
