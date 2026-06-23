set dotenv-load := true

# List recipes.
default:
    just --list

# Build the debug binary.
build:
    cargo build

# Build the release binary.
release:
    cargo build --release --locked

# Format the whole workspace.
fmt:
    cargo fmt --all

# Run the full test suite (unit + integration against the offline fixtures).
test:
    cargo test --workspace

# The gate: formatting, lints, tests, and a battery of real-fixture smoke checks.
verify:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo build --workspace
    # generated bodies round-trip through check
    cargo run --quiet -- generate regbody | cargo run --quiet -- check -
    # over-broad generation must block
    sh -c 'if cargo run --quiet -- generate regbody --over-broad | cargo run --quiet -- check -; then exit 1; else exit 0; fi'
    # the proportionate / over-broad example bodies
    cargo run --quiet -- check examples/min.json
    sh -c 'if cargo run --quiet -- check examples/over.json; then exit 1; else exit 0; fi'
    # over-ask audit
    cargo run --quiet -- audit --request minimal --purpose event_checkin
    sh -c 'if cargo run --quiet -- audit --request overask --purpose event_checkin; then exit 1; else exit 0; fi'
    # cryptographic verification against the committed ERICA fixtures
    cargo run --quiet -- verify presentation fixtures/presentations/erica-vp-VALID.sdjwt --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b --aud https://self-issued.me/v2 --now 1780435200
    cargo run --quiet -- verify trust fixtures/presentations/erica-vp-VALID.sdjwt --anchor fixtures/certs/erica-trust-anchor.pem --now 1780435200
    # the x509_hash binding matches the captured leaf
    cargo run --quiet -- x509-hash fixtures/certs/access-leaf.pem --client-id x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI
    # the wallet-interaction debugger wires up (help exits without binding a port)
    cargo run --quiet -- serve --help > /dev/null
    cargo run --quiet -- evidence --help > /dev/null
    cargo run --quiet -- cache serve --help > /dev/null
    cargo run --quiet -- cache warm --help > /dev/null
    # the mdoc decoder reads the committed ISO 18013-5 mDL vector
    cargo run --quiet -- decode mdoc fixtures/mdoc/issuer-signed.hex > /dev/null
    # DCQL validation: the committed eudiplo query is clean, a bad one blocks
    cargo run --quiet -- validate dcql fixtures/dcql/eudiplo-haip-pid-de.dcql.json > /dev/null
    sh -c 'if cargo run --quiet -- validate dcql "{\"credentials\":[]}"; then exit 1; else exit 0; fi'

# A presentation-focused proof gate: stable offline commands that support the
# agent-first demo story without sandbox credentials or a live wallet.
demo-proof:
    cargo test --test demo_proof
    cargo test --test serve request_side_and_trace_flow
    ./scripts/serve-smoke.sh
    cargo test --test cache

# Print the stable offline presentation sequence from the bundled plugin binary.
demo-run:
    ./plugins/augenmass-workbench/bin/augenmass --version
    ./plugins/augenmass-workbench/bin/augenmass inspect fixtures/requests/eudiplo-request.jwt
    sh -c './plugins/augenmass-workbench/bin/augenmass doctor examples/bad-request.json; code=$?; test "$code" -eq 1'
    ./plugins/augenmass-workbench/bin/augenmass decode regcert fixtures/regcert/rc-by-id.json
    sh -c './plugins/augenmass-workbench/bin/augenmass audit --request minimal --purpose age_gate_18 --cert fixtures/regcert/rc-by-id.json; code=$?; test "$code" -eq 1'
    ./plugins/augenmass-workbench/bin/augenmass check examples/min.json
    sh -c './plugins/augenmass-workbench/bin/augenmass check examples/over.json; code=$?; test "$code" -eq 1'
    ./plugins/augenmass-workbench/bin/augenmass verify presentation fixtures/presentations/erica-vp-VALID.sdjwt --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b --aud https://self-issued.me/v2 --now 1780435200 --trust-anchor fixtures/certs/erica-trust-anchor.pem
    sh -c './plugins/augenmass-workbench/bin/augenmass verify presentation fixtures/presentations/synthetic-pid-with-status.sdjwt --nonce b4ba2623-76a2-486b-a1f6-f1656025d07b --aud https://self-issued.me/v2 --now 1780435200 --trust-anchor fixtures/certs/synthetic-pid-anchor.pem --status-token fixtures/status/status-list-REVOKED.jwt --status-key fixtures/status/status-list-verify-key.pub.pem; code=$?; test "$code" -eq 1'

# Verify the plugin bundle front door without needing Claude Code itself.
plugin-smoke:
    ./scripts/plugin-smoke.sh

# Verify Claude Code can validate and install the local plugin from this repo marketplace.
claude-plugin-smoke:
    ./scripts/claude-plugin-smoke.sh

# Verify Codex can install the local plugin from this repo marketplace.
codex-plugin-smoke:
    ./scripts/codex-plugin-smoke.sh

# Verify a fresh source install into an isolated local root.
install-smoke:
    ./scripts/install-smoke.sh

# Verify the self-contained release archive layout before tagging.
release-archive-smoke: release
    bash -c 'set -euo pipefail; target="$(rustc -vV | sed -n "s/^host: //p")"; binary="augenmass"; case "${target}" in *windows*) binary="augenmass.exe";; esac; out="dist/local-release-archive-smoke"; rm -rf "${out}"; mkdir -p "${out}"; archive="$(./scripts/package-release-archive.sh "${target}" "target/release/${binary}" tar.gz "${out}")"; ./scripts/release-archive-smoke.sh "${archive}"'

# Verify the live cached-sandbox path against the public sandbox API.
live-cache-smoke:
    ./scripts/live-cache-smoke.sh

# Print a no-credentials aggregate snapshot of public sandbox reads.
public-sandbox-snapshot:
    ./scripts/public-sandbox-snapshot.sh

# Verify an already deployed cache backend when AUGENMASS_DEPLOYED_CACHE_API_BASE is set.
deployed-cache-smoke:
    ./scripts/deployed-cache-smoke.sh

# Verify the bundled verifier-in-a-box runtime over loopback HTTP.
serve-smoke:
    ./scripts/serve-smoke.sh

# Verify live sandbox configuration without mutating it by default.
live-sandbox-smoke:
    ./scripts/live-sandbox-smoke.sh

# Build and run the cache backend container locally.
docker-smoke:
    ./scripts/docker-smoke.sh

# Build and run the cache backend container as Linux arm64.
docker-smoke-arm64:
    AUGENMASS_DOCKER_PLATFORM=linux/arm64 AUGENMASS_DOCKER_IMAGE=augenmass-cache-smoke-arm64 AUGENMASS_DOCKER_SMOKE_PORT=18986 ./scripts/docker-smoke.sh

# Build and run the cache backend container as Linux amd64.
docker-smoke-amd64:
    AUGENMASS_DOCKER_PLATFORM=linux/amd64 AUGENMASS_DOCKER_IMAGE=augenmass-cache-smoke-amd64 AUGENMASS_DOCKER_SMOKE_PORT=18985 ./scripts/docker-smoke.sh

# Build and smoke a Linux arm64 release archive inside Docker.
docker-release-archive-smoke-arm64:
    ./scripts/docker-release-archive-smoke.sh linux/arm64

# Build and smoke a Linux amd64 release archive inside Docker.
docker-release-archive-smoke-amd64:
    ./scripts/docker-release-archive-smoke.sh linux/amd64

# Build and smoke Linux release archives inside Docker for both supported local proof platforms.
docker-release-archive-smoke-linux: docker-release-archive-smoke-arm64 docker-release-archive-smoke-amd64

# Check host and available cross-target builds without remote CI.
platform-smoke:
    ./scripts/platform-smoke.sh

# Local shipping proof that avoids remote GitHub CI runner credits.
shipping-smoke: plugin-smoke claude-plugin-smoke codex-plugin-smoke serve-smoke live-cache-smoke deployed-cache-smoke docker-smoke

# Strongest local release proof; no GitHub Actions, but multiple Linux Docker builds.
local-release-proof: verify demo-run plugin-smoke claude-plugin-smoke codex-plugin-smoke serve-smoke install-smoke release-archive-smoke live-cache-smoke platform-smoke docker-smoke-arm64 docker-smoke-amd64 docker-release-archive-smoke-linux

# Bundle the release binary into the plugin (Apple Silicon macOS).
bundle: release
    mkdir -p plugins/augenmass-workbench/bin
    cp target/release/augenmass plugins/augenmass-workbench/bin/augenmass

# Demo: run the local clone store.
demo:
    cargo run -- clone serve --db ./demo.sqlite --port 8080

# Debug a live wallet interaction: the verifier-in-a-box with a full trace.
serve:
    cargo run -- serve
