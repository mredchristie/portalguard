#!/bin/sh
# Answer every name with PORTAL_IP. `address=/#/<ip>` is dnsmasq's wildcard
# form, and it is deliberately total: a hijacked resolver that answered only
# some names would not reproduce what hotel networks actually do.
set -eu

: "${PORTAL_IP:?set PORTAL_IP to the address the portal is reachable on}"

echo "dnsmasq: answering every query with ${PORTAL_IP}"
exec dnsmasq \
  --keep-in-foreground \
  --no-resolv \
  --no-hosts \
  --log-facility=- \
  --log-queries \
  --address="/#/${PORTAL_IP}"
