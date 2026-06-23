FROM rust:1.92-bookworm AS build

WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 augenmass \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin augenmass \
    && mkdir -p /data \
    && chown -R augenmass:augenmass /data

COPY --from=build /app/target/release/augenmass /usr/local/bin/augenmass

ENV AUGENMASS_CACHE_HOST=0.0.0.0
ENV AUGENMASS_CACHE_DB=/data/augenmass-cache.sqlite

VOLUME ["/data"]
EXPOSE 8081

USER augenmass
CMD ["augenmass", "cache", "serve"]
