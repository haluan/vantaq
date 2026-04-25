# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY include ./include
COPY src ./src
COPY Makefile ./Makefile

RUN make build

FROM debian:bookworm-slim AS runtime

RUN mkdir -p /etc/vantaqd \
    && printf '%s\n' '{"service": {"listen_host": "0.0.0.0", "listen_port": 8080}}' > /etc/vantaqd/vantaqd.json

COPY --from=builder /workspace/bin/vantaqd /usr/local/bin/vantaqd

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vantaqd"]
CMD []
