param(
    [string]$SdkRoot = "",
    [string]$Apk = "",
    [string]$Avd = "",
    [string]$Key = "",
    [string]$Source1 = "D:\02.SrcCode\04.others\bookSource_1.json",
    [string]$Source2 = "D:\02.SrcCode\04.others\bookSource_2.json",
    [string]$Out = "D:\02.SrcCode\04.others\test\001.book_src_test",
    [int]$ProxyPort = 8899,
    [int]$ChapterIndex = 0,
    [switch]$SkipUi
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if (-not $SdkRoot) {
    $candidates = @(
        "$env:ANDROID_SDK_ROOT",
        "$env:ANDROID_HOME",
        "$env:LOCALAPPDATA\Android\Sdk",
        "$env:USERPROFILE\AppData\Local\Android\Sdk"
    ) | Where-Object { $_ -and (Test-Path (Join-Path $_ "platform-tools\adb.exe")) }
    if (-not $candidates) {
        throw "Android SDK not found. Pass -SdkRoot <path to Android\Sdk>."
    }
    $SdkRoot = $candidates[0]
}

if (-not $Apk) {
    $found = Get-ChildItem (Join-Path $repo "app\build\outputs\apk\app\debug\*.apk") -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $found) {
        throw "No APK found. Build it first:  .\gradlew :app:assembleAppDebug"
    }
    $Apk = $found.FullName
}

if (-not (Test-Path $Apk)) { throw "APK not found: $Apk" }
if (-not (Test-Path $Source1)) { throw "Book source JSON not found: $Source1" }
if (-not (Test-Path $Source2)) { throw "Book source JSON not found: $Source2" }

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { throw "Python 3.9+ is required (python not in PATH)." }

$venv = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating venv ..." -ForegroundColor Cyan
    & python -m venv $venv
}

Write-Host "Installing dependencies ..." -ForegroundColor Cyan
& $venvPython -m pip install --disable-pip-version-check -q -r (Join-Path $PSScriptRoot "requirements.txt")

$scriptArgs = @(
    "-u", (Join-Path $PSScriptRoot "run_capture.py"),
    "--sdk-root", $SdkRoot,
    "--apk", $Apk,
    "--source1", $Source1,
    "--source2", $Source2,
    "--out-dir", $Out,
    "--proxy-port", $ProxyPort,
    "--chapter-index", $ChapterIndex
)
if ($Avd) { $scriptArgs += @("--avd", $Avd) }
if ($Key) { $scriptArgs += @("--key", $Key) }
if ($SkipUi) { $scriptArgs += "--skip-ui" }

& $venvPython @scriptArgs
exit $LASTEXITCODE
