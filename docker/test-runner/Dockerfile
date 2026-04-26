# syntax=docker/dockerfile:1

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests
COPY docker/test-runner/run-health-check.sh /usr/local/bin/run-health-check.sh
RUN chmod +x /usr/local/bin/run-health-check.sh

ENTRYPOINT ["/usr/local/bin/run-health-check.sh"]
