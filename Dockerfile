# syntax=docker/dockerfile:1
# The avianlink relay (docs/relay.md), in a minimal image.
#
#   docker build -t avianlink-relay .
#   docker run -d --init --name avianlink-relay -p 41000:41000/udp \
#       -v avianlink-relay:/data avianlink-relay
#
# Arguments after the image name replace the defaults below, for example
#   ... avianlink-relay --retention-days 30 --push-service push.avianlink.dev:41001
#
# Use --init (or `init: true`, as in deploy/docker-compose.yml): the relay
# installs no signal handler, so as PID 1 it would ignore `docker stop`
# until killed. Nothing is lost either way; every packet is on disk before
# it is receipted.

FROM rust:1.92-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p avianlink-udp --bin avianlink-relay \
    && cp target/release/avianlink-relay /avianlink-relay \
    && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /avianlink-relay /usr/local/bin/avianlink-relay
# Owned by the image's non-root user, so a new volume is writable.
COPY --from=build --chown=65532:65532 /data /data
VOLUME /data
EXPOSE 41000/udp
ENTRYPOINT ["/usr/local/bin/avianlink-relay", "--dir", "/data", "--bind", "0.0.0.0:41000"]
CMD ["--retention-days", "7"]
