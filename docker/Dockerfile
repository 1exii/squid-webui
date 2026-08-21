# Squid with SSL-bump support (uses squid-openssl package, not plain squid)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        squid-openssl \
        iptables \
        tzdata \
        tcpdump \
        iproute2 \
        net-tools \
        procps \
        tini \
        curl \
        netcat-traditional \
        ca-certificates \
        python3 && \
    rm -rf /var/lib/apt/lists/*

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 3128 3129 3130

ENTRYPOINT ["/usr/bin/tini", "--", "/docker-entrypoint.sh"]
