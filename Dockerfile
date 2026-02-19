FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /faceproxy .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /faceproxy /faceproxy
EXPOSE 8080
ENTRYPOINT ["/faceproxy"]
