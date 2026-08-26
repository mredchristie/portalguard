# A resolver that answers every query with the portal's address, which is what
# a captive portal does and what Portalguard's DNS hijack check looks for.
FROM alpine:3.21
RUN apk add --no-cache dnsmasq
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
