[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$bashScript = Join-Path $scriptDir "snare"

$bashPath = $null
$candidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files\Git\usr\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)

foreach ($c in $candidates) {
    if (Test-Path $c) {
        $bashPath = $c
        break
    }
}

if (-not $bashPath) {
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd) {
        $gitDir = Split-Path -Parent (Split-Path -Parent $gitCmd.Source)
        $potential = Join-Path $gitDir "bin\bash.exe"
        if (Test-Path $potential) { $bashPath = $potential }
    }
}

if (-not $bashPath) {
    $bashCmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($bashCmd -and $bashCmd.Source -notlike "*System32*") {
        $bashPath = $bashCmd.Source
    }
}

if (-not $bashPath) {
    Write-Error "Git Bash is required to run snare on Windows. Please install Git for Windows: winget install Git.Git"
    exit 1
}

& $bashPath $bashScript @ScriptArgs
exit $LASTEXITCODE
