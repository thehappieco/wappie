# Build from the PUBLIC repository root: docker build -f deploy/Dockerfile .
FROM golang:1.26.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY packages/client/testdata/ ./packages/client/testdata/
RUN CGO_ENABLED=0 go build -trimpath -o /out/whatserverd ./cmd/whatserverd && \
    CGO_ENABLED=0 go build -trimpath -o /out/wsctl ./cmd/wsctl
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /app/bin/
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["/app/bin/whatserverd"]
