param(
    [Parameter(Mandatory=$true)][string]$RustCheckout,
    [string]$GoCommand = 'go',
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$goRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$rustRoot = (Resolve-Path $RustCheckout).Path
$pin = '8f16c0f78673461ba41c184e71d29a6492be571c'
$head = git -C $rustRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $head -ne $pin) { throw 'Rust checkout must be at the exact documented commit' }
$module = Join-Path $rustRoot 'sdk\src\live_video\vsi_signing.rs'
$adapter = Join-Path $rustRoot 'sdk\src\live_video\go_interop_harness.rs'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'go_interop_harness.rs') -Destination $adapter
$source = [IO.File]::ReadAllText($module)
$registration = "`n#[cfg(test)]`n#[path = `"go_interop_harness.rs`"]`nmod go_interop_harness;"
$baseSource = (git -C $rustRoot show 'HEAD:sdk/src/live_video/vsi_signing.rs') -join "`n"
$normalized = $source.Replace("`r`n", "`n").Replace($registration, '').TrimEnd()
$otherChanges = @(git -C $rustRoot diff HEAD --name-only | Where-Object { $_ -ne 'sdk/src/live_video/vsi_signing.rs' })
if ($normalized -ne $baseSource.TrimEnd() -or $otherChanges.Count -ne 0) {
    throw 'Rust production sources must match the pinned commit; use a dedicated clean checkout'
}
if (-not $source.Contains('mod go_interop_harness;')) {
    [IO.File]::AppendAllText($module, $registration + "`n")
}
# Only a test module is installed. Review the checkout diff before running.
$savedEnvironment = @{}
foreach ($name in @('C2PA_INTEROP_INPUT','C2PA_INTEROP_RUST','C2PA_INTEROP_GO','C2PA_INTEROP_CREDENTIALS','C2PA_INTEROP_ROTATION')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
$env:C2PA_INTEROP_INPUT = Join-Path $goRoot 'testdata\live_video\livesim2'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('c2pa-interop-' + [Guid]::NewGuid().ToString('N')) }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $goRoot 'testdata'))
if ($outputRoot.Equals($fixtureRoot, [StringComparison]::OrdinalIgnoreCase) -or $outputRoot.StartsWith($fixtureRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Use an output directory outside reviewed testdata; fixture replacement is a separate review step' }
$env:C2PA_INTEROP_RUST = Join-Path $outputRoot 'rust'
$env:C2PA_INTEROP_GO = Join-Path $outputRoot 'go'
$env:C2PA_INTEROP_CREDENTIALS = Join-Path $outputRoot 'credentials'
$env:C2PA_INTEROP_ROTATION = Join-Path $env:C2PA_INTEROP_CREDENTIALS 'rotation'
Push-Location $goRoot
try {
    & $GoCommand test -run '^TestLiveInteropGenerate(Go|Rotation)$' -count=1 -v .
    if ($LASTEXITCODE -ne 0) { throw 'Go generation failed' }
} finally { Pop-Location }
Push-Location $rustRoot
try {
    cargo test -p c2pa --locked --no-default-features --features rust_native_crypto,unstable_live_video --lib go_interop_ -- --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'Rust interoperability checks failed' }
} finally { Pop-Location }
Push-Location $goRoot
try {
    & $GoCommand test -run '^TestLiveInteropRustToGo$' -count=1 -v .
    if ($LASTEXITCODE -ne 0) { throw 'Go interoperability checks failed' }
} finally { Pop-Location }
Write-Host "Both directions and rotation passed. Output directory: $outputRoot"
Write-Host 'Reviewed fixtures were preserved. Replacing them requires a separate byte/provenance/checksum review.'
Write-Host "Test credential directory: $env:C2PA_INTEROP_CREDENTIALS"
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
