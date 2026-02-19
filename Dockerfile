FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /faceproxy .

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gnupg ca-certificates && \
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
      > /etc/apt/sources.list.d/cloudflare-client.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends cloudflare-warp && \
    apt-get purge -y curl gnupg && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /faceproxy /faceproxy
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
