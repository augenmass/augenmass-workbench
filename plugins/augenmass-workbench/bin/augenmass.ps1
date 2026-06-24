$ErrorActionPreference = "Stop"

if ($env:AUGENMASS_BIN) {
    & $env:AUGENMASS_BIN @args
    exit $LASTEXITCODE
}

$bin = Join-Path $PSScriptRoot "x86_64-pc-windows-msvc\augenmass.exe"

if (-not (Test-Path -LiteralPath $bin)) {
    Write-Error "Missing Augenmass binary: $bin. Install a native release archive or rebuild the plugin bundle, then set AUGENMASS_BIN if needed."
    exit 127
}

& $bin @args
$status = $LASTEXITCODE

if ($status -eq 126) {
    Write-Error @"
Augenmass could not run the selected binary.

These preview binaries are not code-signed yet. Verify the release/checksum
first. Then right-click augenmass.exe -> Properties -> Unblock, or run:

  Unblock-File .\augenmass.exe
"@
}

exit $status
