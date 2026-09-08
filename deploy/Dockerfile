FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY ca.crt /usr/local/share/ca-certificates/wappie.crt
RUN update-ca-certificates
COPY bin/ /app/bin/
COPY web/ /app/web/
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["/app/bin/whatserverd"]
