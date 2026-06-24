#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  set -- augenmass cache serve
fi

if [ "$(id -u)" = "0" ]; then
  db_path="${AUGENMASS_CACHE_DB:-/data/augenmass-cache.sqlite}"
  data_dir="$(dirname "${db_path}")"
  mkdir -p "${data_dir}"
  chown -R 10001:10001 "${data_dir}"
  exec gosu 10001:10001 "$@"
fi

exec "$@"
