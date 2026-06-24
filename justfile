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

# Print the stable offline presentation sequence from the resolved CLI binary.
demo-run:
    ./scripts/demo-run.sh

# Print the stable offline presentation sequence from the bundled plugin binary.
plugin-demo-run:
    env -u AUGENMASS_DEMO_BIN -u AUGENMASS_BIN ./scripts/demo-run.sh

# Verify the plugin bundle front door without needing Claude Code itself.
plugin-smoke:
    ./scripts/plugin-smoke.sh

# Verify the committed plugin binary is byte-for-byte the current release build.
plugin-bundle-freshness:
    ./scripts/plugin-bundle-freshness.sh

# Verify the installed plugin/skill remains useful without a full repo checkout.
plugin-only-smoke:
    ./scripts/plugin-only-smoke.sh

# Verify Claude Code can validate and install the local plugin from this repo marketplace.
claude-plugin-smoke:
    ./scripts/claude-plugin-smoke.sh

# Verify Codex can install the local plugin from this repo marketplace.
codex-plugin-smoke:
    ./scripts/codex-plugin-smoke.sh

# Verify GitHub Actions cannot spend runner credits on normal branch pushes.
ci-credit-guard:
    ./scripts/ci-credit-guard.sh

# Verify a fresh source install into an isolated local root.
install-smoke:
    ./scripts/install-smoke.sh

# Verify the self-contained release archive layout before tagging.
release-archive-smoke: release
    bash -c 'set -euo pipefail; target="$(rustc -vV | sed -n "s/^host: //p")"; binary="augenmass"; package_ext="tar.gz"; case "${target}" in *windows*) binary="augenmass.exe"; package_ext="zip";; esac; out="dist/local-release-archive-smoke"; rm -rf "${out}"; mkdir -p "${out}"; archive="$(./scripts/package-release-archive.sh "${target}" "target/release/${binary}" "${package_ext}" "${out}")"; ./scripts/release-archive-smoke.sh "${archive}"'

# Verify the Windows-style zip package layout locally without claiming native Windows proof.
release-zip-layout-smoke: release
    ./scripts/release-zip-layout-smoke.sh

# Verify the live cached-sandbox path against the public sandbox API.
live-cache-smoke:
    ./scripts/live-cache-smoke.sh

# Print a no-credentials aggregate snapshot of public sandbox reads.
public-sandbox-snapshot:
    ./scripts/public-sandbox-snapshot.sh

# Verify an already deployed cache backend when AUGENMASS_DEPLOYED_CACHE_API_BASE is set.
deployed-cache-smoke:
    ./scripts/deployed-cache-smoke.sh

# Verify required hosted-cache proof refuses local or insecure API bases.
deployed-cache-guard-smoke:
    ./scripts/deployed-cache-guard-smoke.sh

# Require and verify an already deployed cache backend before claiming hosted readiness.
deployed-cache-smoke-required:
    AUGENMASS_DEPLOYED_CACHE_REQUIRED=1 ./scripts/deployed-cache-smoke.sh

# Required hosted backend proof before claiming a deployed cache is ready.
hosted-release-proof: deployed-cache-smoke-required

# Typecheck the optional Cloudflare Containers Worker adapter without deploying it.
cloudflare-containers-typecheck:
    cd deploy/cloudflare-containers && bun install --frozen-lockfile && bun run typecheck

# Verify the bundled verifier-in-a-box runtime over loopback HTTP.
serve-smoke:
    ./scripts/serve-smoke.sh

# Verify live sandbox configuration without mutating it by default.
live-sandbox-smoke:
    ./scripts/live-sandbox-smoke.sh

# Require live sandbox credentials and verify the non-mutating sandbox path.
live-sandbox-smoke-required:
    AUGENMASS_LIVE_SANDBOX_REQUIRED=1 ./scripts/live-sandbox-smoke.sh

# Required live sandbox proof before claiming the real sandbox path is configured.
sandbox-readiness-proof: live-sandbox-smoke-required

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

# Require every configured platform target to be installed and checkable.
platform-smoke-strict:
    AUGENMASS_STRICT_PLATFORM_SMOKE=1 ./scripts/platform-smoke.sh

# Fail fast before the long plugin-free local CLI release proof.
local-cli-release-preflight:
    ./scripts/local-release-preflight.sh cli

# Fail fast before the presenter plugin proof.
presenter-release-preflight:
    ./scripts/local-release-preflight.sh presenter

# Plugin-free local CLI release proof, suitable for non-plugin platform checks.
local-cli-release-proof: local-cli-release-preflight ci-credit-guard verify release install-smoke release-archive-smoke release-zip-layout-smoke platform-smoke docker-smoke-arm64 docker-smoke-amd64 docker-release-archive-smoke-linux
    ./scripts/local-cli-release-smokes.sh

# Presenter plugin proof for the committed macOS Apple Silicon plugin bundle.
presenter-plugin-proof: presenter-release-preflight plugin-bundle-freshness plugin-smoke plugin-only-smoke claude-plugin-smoke codex-plugin-smoke plugin-demo-run

# Local shipping proof that avoids remote GitHub CI runner credits.
shipping-smoke: ci-credit-guard plugin-bundle-freshness plugin-smoke plugin-only-smoke claude-plugin-smoke codex-plugin-smoke serve-smoke live-cache-smoke public-sandbox-snapshot deployed-cache-guard-smoke deployed-cache-smoke cloudflare-containers-typecheck docker-smoke

# Strongest local release proof; no GitHub Actions, but multiple Linux Docker builds.
local-release-proof: local-cli-release-proof presenter-plugin-proof

# Bundle the release binary into the plugin (Apple Silicon macOS).
bundle: release
    bash -c 'set -euo pipefail; target="$(rustc -vV | sed -n "s/^host: //p")"; test "$target" = "aarch64-apple-darwin" || { echo "bundle writes the committed plugin binary and must run on aarch64-apple-darwin (got ${target})" >&2; exit 1; }; mkdir -p plugins/augenmass-workbench/bin; cp target/release/augenmass plugins/augenmass-workbench/bin/augenmass'

# Demo: run the local clone store.
demo:
    cargo run -- clone serve --db ./demo.sqlite --port 8080

# Debug a live wallet interaction: the verifier-in-a-box with a full trace.
serve:
    cargo run -- serve
