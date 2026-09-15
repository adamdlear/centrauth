FROM golang:1.27 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o centrauth ./cmd/centrauth

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/centrauth /usr/local/bin/centrauth
ENTRYPOINT ["centrauth"]
