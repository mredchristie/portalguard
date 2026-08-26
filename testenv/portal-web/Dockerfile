# Build context is the repository root, so the fake portal is built from the
# same module as portalguard itself and cannot drift from it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
# No third-party dependencies yet; the copy is here so the layer caches once
# a go.sum appears.
COPY . .
RUN CGO_ENABLED=0 go build -o /out/fakeportal ./testenv/portal-web

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/fakeportal /usr/local/bin/fakeportal
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/fakeportal", "-addr", ":80"]
