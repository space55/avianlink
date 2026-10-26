# Runtime image for the netem acceptance test: Debian with iproute2 (tc,
# ip), awk and od for the generated netem scripts.
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 gawk procps iputils-ping \
    && rm -rf /var/lib/apt/lists/*
