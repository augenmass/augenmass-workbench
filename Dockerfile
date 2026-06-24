FROM rust:1.92-bookworm AS build

WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM build AS release-archive
RUN set -eux; \
    target="$(rustc -vV | sed -n 's/^host: //p')"; \
    ./scripts/package-release-archive.sh "${target}" target/release/augenmass tar.gz /dist

FROM debian:bookworm-slim AS release-archive-smoke
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates gzip tar \
    && rm -rf /var/lib/apt/lists/*
COPY --from=release-archive /dist/ /dist/
COPY --from=release-archive /app/scripts/release-archive-smoke.sh /usr/local/bin/release-archive-smoke.sh
RUN bash -lc 'set -euo pipefail; archives=(/dist/*.tar.gz); test "${#archives[@]}" -eq 1; bash /usr/local/bin/release-archive-smoke.sh "${archives[0]}"'

FROM scratch AS release-archive-export
COPY --from=release-archive-smoke /dist/ /

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 augenmass \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin augenmass \
    && mkdir -p /data \
    && chown -R augenmass:augenmass /data

COPY --from=build /app/target/release/augenmass /usr/local/bin/augenmass
COPY scripts/docker-entrypoint.sh /usr/local/bin/augenmass-docker-entrypoint
RUN chmod +x /usr/local/bin/augenmass-docker-entrypoint

ENV AUGENMASS_CACHE_HOST=0.0.0.0
ENV AUGENMASS_CACHE_DB=/data/augenmass-cache.sqlite

VOLUME ["/data"]
EXPOSE 8081

ENTRYPOINT ["augenmass-docker-entrypoint"]
CMD ["augenmass", "cache", "serve"]
