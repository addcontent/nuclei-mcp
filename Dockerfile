# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/nuclei-mcp ./cmd/nuclei-mcp

# Runtime stage
FROM alpine:3.22

RUN apk --no-cache add ca-certificates \
 && addgroup -g 1001 -S nuclei \
 && adduser -u 1001 -S nuclei -G nuclei -h /home/nuclei

COPY --from=builder /out/nuclei-mcp /usr/local/bin/nuclei-mcp

USER nuclei
WORKDIR /home/nuclei
# Templates are embedded in the binary and copied to ~/.nuclei-mcp/templates
# on first run. Mount a volume there to keep your own templates.
ENV NUCLEI_MCP_LOGGING_PATH=""

# MCP over stdio: run with `docker run -i --rm nuclei-mcp`.
# There is no network port and no health check: the process lives exactly as
# long as the client keeps stdin open.
ENTRYPOINT ["/usr/local/bin/nuclei-mcp"]
