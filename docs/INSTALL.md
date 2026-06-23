# Install and first run

Augenmaß Workbench has two entry points:

- The Claude Code skill, for plain-language EUDI help.
- The `augenmass` Rust CLI, for terminal use, hooks, and CI.

Both surfaces call the same binary.

## Claude Code skill

Private preview install:

```text
/plugin marketplace add augenmass/augenmass-workbench
/plugin install augenmass-workbench@augenmass
```

The bundled plugin binary in this repository is currently macOS Apple Silicon.
Inside the skill, agents should call the bundled binary on macOS Apple Silicon:

```sh
"${CLAUDE_PLUGIN_ROOT}/bin/augenmass" --help
```

Use bare `augenmass` only when the plugin `bin/` directory, a source install, or
a release archive has placed it on `PATH`.

On other platforms, build or install the CLI first, then tell the agent where it
is:

```sh
export AUGENMASS_BIN="$HOME/.local/bin/augenmass"
```

The skill should use `AUGENMASS_BIN` when that variable is set.

## Source install

Use this on macOS or Linux when you have Rust 1.92 available:

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

The release-archive gate is:

```sh
just release-archive-smoke
```

It builds the host archive layout, extracts it into a temporary directory, then
runs the packaged binary against packaged docs, examples, and fixtures. This is
the local check that the downloaded archive is self-contained.

The broader local release proof is:

```sh
just local-release-proof
```

That adds workspace verification, release archive proof, the plugin bundle
smoke, live cached-sandbox proof, macOS target probing, and explicit Linux arm64
and amd64 Docker build-and-run checks. It does not spend runner credits.
