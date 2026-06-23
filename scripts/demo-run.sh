#!/usr/bin/env bash
set -euo pipefail

BIN="${AUGENMASS_DEMO_BIN:-${AUGENMASS_BIN:-./plugins/augenmass-workbench/bin/augenmass}}"

if [ ! -x "${BIN}" ]; then
  echo "demo binary is not executable: ${BIN}" >&2
  exit 1
fi

"${BIN}" --version
"${BIN}" inspect fixtures/requests/eudiplo-request.jwt
if "${BIN}" doctor examples/bad-request.json; then
  echo "expected doctor examples/bad-request.json to fail" >&2
  exit 1
fi
"${BIN}" decode regcert fixtures/regcert/rc-by-id.json
if "${BIN}" audit --request minimal --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json; then
  echo "expected audit minimal age_gate_18 with over-broad cert to fail" >&2
  exit 1
fi
"${BIN}" check examples/min.json
if "${BIN}" check examples/over.json; then
  echo "expected examples/over.json to fail" >&2
  exit 1
fi
"${BIN}" verify presentation fixtures/presentations/erica-vp-VALID.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200 \
  --trust-anchor fixtures/certs/erica-trust-anchor.pem
if "${BIN}" verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt \
  --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b \
  --aud https://self-issued.me/v2 \
  --now 1780435200 \
  --trust-anchor fixtures/certs/synthetic-pid-anchor.pem \
  --status-token fixtures/status/status-list-REVOKED.jwt \
  --status-key fixtures/status/status-list-verify-key.pub.pem; then
  echo "expected revoked synthetic presentation to fail" >&2
  exit 1
fi
