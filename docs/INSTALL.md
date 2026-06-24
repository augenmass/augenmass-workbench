# Install and first run

Augenmaß Workbench has two entry points:

- The Claude Code and Codex skills, for plain-language EUDI help.
- The `augenmass` Rust CLI, for terminal use, hooks, and CI.

Both surfaces call the same binary.

## Claude Code skill

Private preview install:

```text
/plugin marketplace add augenmass/augenmass-workbench
/plugin install augenmass-workbench@augenmass
```

## Codex skill

The repository includes a Codex plugin manifest and a local marketplace file. To
install from a local checkout:

```sh
codex plugin marketplace add .
codex plugin add augenmass-workbench@augenmass
```

After a public release, the marketplace source can be the GitHub repository
instead of a local checkout:

```sh
codex plugin marketplace add augenmass/augenmass-workbench --ref main
codex plugin add augenmass-workbench@augenmass
```

The plugin includes a bundled launcher and native preview binaries for macOS
Apple Silicon, macOS Intel, Linux x64, and Windows x64. The skill should work
without a separate source build on those targets. Set `AUGENMASS_BIN` only when
you want to override the bundled binary, use an unsupported target, or point the
skill at a binary you built yourself.

## First run in an agent

After installing the plugin, start with the skill, not the terminal. These
prompts are safe even when the plugin was installed without the full repo
checkout:

| Audience | Prompt | Expected outcome |
| --- | --- | --- |
| Developer | `Use the augenmass skill: show the purpose baselines, generate a proportionate age-check body, and check it.` | The agent runs no-file commands, explains the generated minimal body, and confirms it passes the over-ask gate. |
| Auditor | `Use the augenmass skill: explain why a full birthdate is too much for an over-18 check, and cite the basis.` | The agent explains the proportionality concern, cites the data-minimisation basis, and proposes `age_equal_or_over.18`. |
| Non-technical reviewer | `Use the augenmass skill: in plain language, what should an age-check service ask for and what should it avoid?` | The agent avoids JSON detail, names the unnecessary data, explains the risk, and gives the safer replacement. |

If you are working from the full repository checkout, you can also ask fixture
prompts such as `inspect fixtures/requests/eudiplo-request.jwt` or
`is examples/over.json over-asking for an age check?`. Those paths are checkout
fixtures, not files guaranteed by every plugin marketplace installation.

For live wallet debugging, ask for the workflow first: `Use the augenmass skill:
prepare a safe live wallet debug run with redacted traces.` The agent should
explain `serve`, `--public-url`, trust/status caveats, and why
`--unsafe-debug-artifacts` is opt-in local sensitive capture.

The bundled plugin command is a launcher. On macOS and Linux, agents should call:

```sh
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" --help
```

On Windows, agents should call one of the Windows launchers:

```powershell
& "$env:CLAUDE_PLUGIN_ROOT\bin\augenmass.ps1" --help
```

The launcher selects the matching bundled binary from:

```text
plugins/augenmass-workbench/bin/aarch64-apple-darwin/augenmass
plugins/augenmass-workbench/bin/x86_64-apple-darwin/augenmass
plugins/augenmass-workbench/bin/x86_64-unknown-linux-gnu/augenmass
plugins/augenmass-workbench/bin/x86_64-pc-windows-msvc/augenmass.exe
```

Use bare `augenmass` only when the plugin `bin/` directory, a source install, or
a release archive has placed it on `PATH`.

To override the bundled launcher with a separately installed or source-built
binary, tell the agent where it is:

```sh
export AUGENMASS_BIN="$HOME/.local/bin/augenmass"
```

The skill should use `AUGENMASS_BIN` when that variable is set.

## Signed and unsigned binaries

The release archives and bundled plugin binaries are checksumed and built by
the release workflow. Some macOS ZIP artifacts may also be Developer ID signed
and notarized when produced with `just macos-notarize`; check the release notes
and sidecar proof before assuming a macOS artifact is notarized.

If a macOS binary is not notarized, or if Gatekeeper still blocks a first run,
verify the release archive and checksum first. If you trust the binary, try
running it once, then open System Settings -> Privacy & Security and choose Open
Anyway for Augenmass. If you do not want to approve an unsigned binary, build
from source with `cargo build --release --locked` and set `AUGENMASS_BIN`.

On Windows, the first run may be blocked because `augenmass.exe` is unsigned or
downloaded from the Internet. Verify the source/checksum first. If you trust the
binary, right-click `augenmass.exe`, choose Properties, and check Unblock; or
run `Unblock-File .\augenmass.exe` in PowerShell.

On Linux, if the file is present but not executable, run `chmod +x` on the
binary.

The runtime smoke gates follow the same convention. `serve-smoke`,
`live-cache-smoke`, `deployed-cache-smoke`, and `live-sandbox-smoke` prefer
`AUGENMASS_BIN` when it is set, then fall back to the bundled plugin launcher.
The plugin-bundle gates intentionally keep using the launcher because they prove
the exact private-preview plugin artifact.
`plugin-only-smoke` copies only the plugin bundle to a temp directory and runs
no-file commands from outside the checkout, proving marketplace-style first-run
behavior without `fixtures/` or `examples/`. `demo-run` is portable too: it
resolves `AUGENMASS_DEMO_BIN`, then `AUGENMASS_BIN`, then the bundled launcher.
Use `plugin-demo-run` for the exact bundled sequence.

## Source install

Use this on macOS or Linux when you have Rust 1.92 available. The current local
proof is strongest on macOS Apple Silicon and Docker Linux; native Linux source
install is expected to work, but should be smoke-tested on the target machine
before you present it as a supported host.

```sh
cargo install --locked --path . --bin augenmass --root "$HOME/.local"
"$HOME/.local/bin/augenmass" --version
"$HOME/.local/bin/augenmass" --help
```

Add `$HOME/.local/bin` to `PATH` if you want to call a bare `augenmass`.

On Windows, the equivalent source build is:

```powershell
cargo build --release --locked
.\target\release\augenmass.exe --version
.\target\release\augenmass.exe --help
```

Native Windows install and archive testing still needs a Windows runner or
machine. Do not claim Windows one-step install until that is proven.

## Local proof

The source-install gate is:

```sh
just install-smoke
```

It installs the CLI into a temporary local Cargo root, checks that the installed
binary is executable, then runs `--version`, `--help`, `inspect`, and a generated
registration body through `check`.

The Codex plugin install gate is:

```sh
just codex-plugin-smoke
```

It uses a temporary `CODEX_HOME`, adds this checkout as a local Codex
marketplace, confirms `augenmass-workbench@augenmass` is available, installs it,
and confirms it is enabled. It does not modify your real Codex config.

The plugin bundle freshness gate is:

```sh
just plugin-bundle-freshness
```

It verifies the plugin bundle manifest version, launcher version, and every
committed target-binary hash. When it fails, refresh the bundle with
`just bundle` and rerun the presenter proof. Set
`AUGENMASS_STRICT_LOCAL_PLUGIN_BUILD=1` only when you explicitly want to compare
the current-host target against a local rebuild; release-built binaries may not
be byte-identical to a local build because build paths can differ.

The Claude Code plugin install gate is:

```sh
just claude-plugin-smoke
```

It uses a temporary `HOME`, validates the plugin and marketplace manifests with
`claude plugin validate --strict`, installs `augenmass-workbench@augenmass` from
this checkout, and confirms the installed plugin is enabled. It does not modify
your real Claude Code config.

The live wallet-debugger runtime gate is:

```sh
just serve-smoke
```

It starts the resolved `augenmass serve` binary on a loopback port, mints a
session, fetches the signed request object, reads the JSON/HTML trace endpoints,
posts a synthetic plaintext `direct_post`, and confirms the trace stays redacted
after the expected HTTP 422 rejection. It does not need a phone wallet or sandbox
credentials.

On Linux, macOS Intel, or Windows Git Bash, build or install a native CLI first
and run this gate with `AUGENMASS_BIN`:

```sh
AUGENMASS_BIN=./target/release/augenmass just serve-smoke
```

On Windows Git Bash, point at the `.exe`:

```sh
AUGENMASS_BIN=./target/release/augenmass.exe just serve-smoke
```

The release-archive gate is:

```sh
just release-archive-smoke
just release-zip-layout-smoke
```

`release-archive-smoke` builds a candidate host archive layout, extracts it into a
temporary directory, then runs the packaged binary against packaged docs,
examples, and fixtures. `release-zip-layout-smoke` exercises the Windows-style
`.zip` package layout locally without claiming native Windows execution unless
the gate is run on Windows. Together they are the local checks that candidate
archives are self-contained.

Each archive produced by the shared packager also gets `<archive>.sha256` and
`<archive>.manifest.json` sidecars. The smoke gate requires and checks those
sidecars by default. From a directory containing a downloaded archive and
sidecar, users can run `shasum -a 256 -c <archive>.sha256` or `sha256sum -c
<archive>.sha256` before extracting. The manifest records the target, archive
hash, binary hash, actual build host, layout-only/native-execution flags, git
commit, dirty flag, and Rust compiler version.

macOS release archives are not notarized yet. Verify the `.sha256` sidecar
before extraction. If Gatekeeper or quarantine blocks the binary, prefer a local
source build until notarized release signing is added.

The broader local release proof is:

```sh
just local-cli-release-proof
just local-release-proof
```

`local-cli-release-proof` is plugin-free: it uses the native release binary for
demo, serve, live cache, install, archive, zip-layout, platform, and Docker
checks. It resolves `./target/release/augenmass` first and falls back to
`./target/release/augenmass.exe`, so Windows Git Bash does not need a different
recipe. `local-release-proof` adds the presenter plugin proof for the committed
platform-aware plugin bundle. Both proofs run a fail-fast preflight before the
long build/test work starts. Together they cover workspace verification, release
archive proof, the plugin bundle smoke, `serve` runtime proof, live
cached-sandbox proof, macOS target probing, explicit Linux arm64 and amd64 Docker
build-and-run checks, and Linux release archives smoke-tested inside matching
Docker containers. The hosted cache and live sandbox readiness gates are
separate because they need external configuration. None of these local gates
spends runner credits.
