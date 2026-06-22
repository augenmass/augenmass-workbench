set dotenv-load := true

# List recipes.
default:
    just --list

# Build the debug binary.
build:
    cargo build

# Build the release binary.
release:
    cargo build --release

# Format the whole workspace.
fmt:
    cargo fmt --all

# Run the full test suite (unit + integration against the offline fixtures).
test:
    cargo test

# The gate: formatting, lints, tests, and a battery of real-fixture smoke checks.
verify:
    cargo fmt --all --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    cargo build
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
    # the mdoc decoder reads the committed ISO 18013-5 mDL vector
    cargo run --quiet -- decode mdoc fixtures/mdoc/issuer-signed.hex > /dev/null

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
