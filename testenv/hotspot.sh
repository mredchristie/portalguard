#!/bin/sh
#
# A BT-shaped captive portal on this Mac, with nothing on loopback.
#
#   ./testenv/hotspot.sh up        # build and start the four hosts
#   ./testenv/hotspot.sh dns-on    # point this Mac's DNS at the portal (sudo)
#   sudo portalguard run           # default probes, no -probes-file
#   ./testenv/hotspot.sh dns-off   # put DNS back (sudo)
#   ./testenv/hotspot.sh down
#
# Each host runs in its own container under Apple's `container` tool, so each
# gets its own address on 192.168.64.0/24, reached over bridge100. pf filters
# that like any other interface, which is the point: testenv/portal-web lives
# on loopback, which the lockdown never filters, so it cannot show whether the
# gap rules work. This can. See testenv/README.md, "The off-box hotspot".
#
# Needs: brew install container && container system start
# Optional: mkcert, with `mkcert -install` already run, for HTTPS on cdn and
# reg - which is what lets `portalguard remember` be tested end to end.
set -eu

cd "$(dirname "$0")/.."

DOMAIN=${DOMAIN:-guestwifi.test}
SERVICE=${SERVICE:-Wi-Fi}
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
DIR=${DIR:-$PWD/bin/hotspot}
SAVED="$DIR/dns.saved"

ip_of() {
    container ls --format json | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    if c["configuration"]["id"] == sys.argv[1]:
        print(c["status"]["networks"][0]["ipv4Address"].split("/")[0])
' "$1"
}

start() {
    name=$1; shift
    container rm -f "$name" >/dev/null 2>&1 || true
    container run -d --name "$name" -v "$DIR:/pg" "$@" "$IMAGE" /pg/hotspot >/dev/null
}

up() {
    command -v container >/dev/null || { echo "needs Apple's container tool: brew install container"; exit 64; }
    # The service does not survive a reboot, and without it every container
    # command fails with an XPC error that does not say why.
    if ! container system status >/dev/null 2>&1; then
        echo "starting the container service..."
        container system start || { echo "could not start it. run: container system start"; exit 64; }
    fi
    mkdir -p "$DIR"
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$DIR/hotspot" ./testenv/hotspot

    if [ ! -f "$DIR/certs/cert.pem" ] && command -v mkcert >/dev/null; then
        mkdir -p "$DIR/certs"
        mkcert -cert-file "$DIR/certs/cert.pem" -key-file "$DIR/certs/key.pem" \
            "www.$DOMAIN" "cdn.$DOMAIN" "reg.$DOMAIN" >/dev/null 2>&1
        echo "certs: issued by mkcert for www, cdn and reg.$DOMAIN"
        echo "       (trusted only if you have run \`mkcert -install\`)"
    fi

    secret=$(openssl rand -hex 16)

    # Every role is the same binary; ROLE picks which one.
    start pg-cdn -e ROLE=cdn
    start pg-reg -e ROLE=reg -e SECRET="$secret"
    start pg-net -e ROLE=net
    # Addresses are only known once the containers exist, and www's DNS has
    # to hand them out, so www goes last.
    cdn=$(ip_of pg-cdn); reg=$(ip_of pg-reg); net=$(ip_of pg-net)
    # www finds its own address inside the container.
    start pg-www -e ROLE=www -e SECRET="$secret" -e DOMAIN="$DOMAIN" \
        -e CDN_IP="$cdn" -e REG_IP="$reg" -e NET_IP="$net"
    www=$(ip_of pg-www)

    echo "$www" > "$DIR/www.ip"
    status
    echo
    echo "next: $0 dns-on, then sudo portalguard run"
}

down() {
    for n in pg-www pg-cdn pg-reg pg-net; do
        container rm -f "$n" >/dev/null 2>&1 || true
    done
    echo "hotspot down"
}

status() {
    for n in www cdn reg net; do
        printf '  %-4s %-16s %s\n' "$n" "$(ip_of "pg-$n" 2>/dev/null || echo -)" \
            "$( [ "$n" = net ] && echo '(the internet, after login)' || echo "$n.$DOMAIN")"
    done
    if [ -f "$DIR/www.ip" ]; then
        printf '  auth %s\n' "$(curl -s -m 2 "http://$(cat "$DIR/www.ip"):8443/status" || echo 'unreachable')"
    fi
}

# dns-on points this Mac's DNS at the portal, the way a hotspot's DHCP would.
# Everything resolves to the portal until login, as on a real one - so the
# Mac is effectively offline until dns-off.
dns_on() {
    www=$(cat "$DIR/www.ip" 2>/dev/null) || { echo "run $0 up first"; exit 64; }
    if [ ! -f "$SAVED" ]; then
        networksetup -getdnsservers "$SERVICE" > "$SAVED"
    fi
    sudo networksetup -setdnsservers "$SERVICE" "$www"
    flush
    echo "DNS for $SERVICE now $www (saved the old setting in $SAVED)"
    grep -q "nameserver $www" /etc/resolv.conf \
        || echo "warning: /etc/resolv.conf does not list $www - is a VPN overriding DNS? disconnect it."
}

dns_off() {
    if [ -f "$SAVED" ] && ! grep -q "aren't any" "$SAVED"; then
        # shellcheck disable=SC2046
        sudo networksetup -setdnsservers "$SERVICE" $(cat "$SAVED")
    else
        sudo networksetup -setdnsservers "$SERVICE" Empty
    fi
    rm -f "$SAVED"
    flush
    echo "DNS for $SERVICE restored"
}

flush() {
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder 2>/dev/null || true
}

reset() {
    curl -s -m 3 -X POST "http://$(cat "$DIR/www.ip"):8443/reset" >/dev/null && echo "portal intercepting again"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    dns-on) dns_on ;;
    dns-off) dns_off ;;
    reset) reset ;;
    *) echo "usage: $0 up | down | status | dns-on | dns-off | reset"; exit 64 ;;
esac
