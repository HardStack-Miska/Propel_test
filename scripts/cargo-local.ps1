param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$env:CARGO_HOME = Join-Path $taskRoot '.tools\cargo'
$env:RUSTUP_HOME = Join-Path $taskRoot '.tools\rustup'
$gnuBin = Join-Path $env:RUSTUP_HOME 'toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained'
$llvmBin = Join-Path $taskRoot '.tools\llvm-mingw-20260908-ucrt-x86_64\bin'
if (-not (Test-Path -LiteralPath (Join-Path $llvmBin 'dlltool.exe'))) {
    throw 'Portable LLVM-MinGW is missing from .tools\llvm-mingw-20260908-ucrt-x86_64; use a standard Rust installation or install the official portable archive first.'
}
# LLVM dlltool assembles import libraries itself. Rust's bundled GNU dlltool
# requires an external as.exe for raw-dylib Windows dependencies.
$env:PATH = "$env:CARGO_HOME\bin;$llvmBin;$gnuBin;$env:PATH"
# Use LLVM's linker with Rust's bundled GNU CRT and support libraries. Explicit
# self-contained linking is needed because rustc does not infer it for clang.
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $llvmBin 'x86_64-w64-mingw32-clang.exe'
if (-not ([string]$env:RUSTFLAGS).EndsWith('-C link-self-contained=yes')) {
    $env:RUSTFLAGS = "$env:RUSTFLAGS -C link-self-contained=yes".Trim()
}
Push-Location $taskRoot
try {
    & (Join-Path $env:CARGO_HOME 'bin\cargo.exe') @CargoArgs
    exit $LASTEXITCODE
} finally {
    Pop-Location
}

