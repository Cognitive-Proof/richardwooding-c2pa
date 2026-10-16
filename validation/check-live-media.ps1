param(
    [string]$GoCommand = 'go',
    [switch]$Fuzz,
    [string]$FuzzTime = '10s',
    [switch]$Race,
    [string]$RustCheckout,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('c2pa-live-checks-' + [Guid]::NewGuid().ToString('N'))
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$coverage = Join-Path $outputRoot 'coverage.out'
$savedProxy = $env:GOPROXY
$savedSumDB = $env:GOSUMDB
$savedInterop = @{}
foreach ($name in @('C2PA_INTEROP_GO','C2PA_INTEROP_RUST','C2PA_INTEROP_CREDENTIALS','C2PA_INTEROP_ROTATION')) {
    $savedInterop[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $root
try {
    # Dependencies/toolchains must already be cached. No fixture regeneration or
    # network download is needed for the ordinary Go gate (tests use localhost).
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    foreach ($name in $savedInterop.Keys) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
    & $GoCommand version
    if ($LASTEXITCODE -ne 0) { throw 'Go is unavailable' }
    $tests = @('test', './...', '-count=1', '-timeout=180s', "-coverprofile=$coverage")
    if ($Race) { $tests += '-race' }
    $checks = @(
        @{ Name = 'Dependency checksums'; Arguments = @('mod', 'verify') },
        @{ Name = 'Build'; Arguments = @('build', './...') },
        @{ Name = 'Vet'; Arguments = @('vet', './...') },
        @{ Name = 'Tests and executable examples'; Arguments = $tests }
    )
    foreach ($check in $checks) {
        Write-Host $check.Name
        $goArguments = $check.Arguments
        & $GoCommand @goArguments
        if ($LASTEXITCODE -ne 0) { throw "$($check.Name) failed" }
    }
    if ($Fuzz) {
        foreach ($target in @('FuzzLiveSessionKeys', 'FuzzLiveVSIEnvelope', 'FuzzLiveVSICarriage', 'FuzzLiveTiming', 'FuzzLiveManifestReference')) {
            & $GoCommand test '-run=^$' "-fuzz=^$target`$" "-fuzztime=$FuzzTime" '-parallel=2' .
            if ($LASTEXITCODE -ne 0) { throw "$target failed" }
        }
    }
    if ($RustCheckout) {
        & (Join-Path $PSScriptRoot 'live-media-interop\run.ps1') -RustCheckout $RustCheckout -GoCommand $GoCommand -OutputDirectory (Join-Path $outputRoot 'interop')
    }
    Write-Host "Go checks passed. Coverage: $coverage"
    if (-not $Race) { Write-Host 'Race detection was not requested; run -Race on a host with CGO and a C compiler.' }
    if (-not $RustCheckout) { Write-Host 'Fresh Rust replay was not requested; retained Rust fixture regressions ran in the Go suite.' }
} finally {
    Pop-Location
    $env:GOPROXY = $savedProxy
    $env:GOSUMDB = $savedSumDB
    foreach ($name in $savedInterop.Keys) { [Environment]::SetEnvironmentVariable($name, $savedInterop[$name], 'Process') }
}
