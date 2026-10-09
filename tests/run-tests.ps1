# run-tests.ps1
# Test runner for mask.ps1 / check.ps1.
#
# Tests:
#   1. mask.ps1 replaces all 15 fake secrets with correct placeholders.
#   2. mask.ps1 inserts [!NOTE] right after Attack Chain.
#   3. mask.ps1 is idempotent (second run does not change output).
#
# Usage:
#   .\tests\run-tests.ps1
#
# Exit codes:
#   0 - all tests passed
#   1 - one or more tests failed

$ErrorActionPreference = "Stop"

$repo = Split-Path $PSScriptRoot -Parent
$fixtures = Join-Path $PSScriptRoot "fixtures"

# --- Setup: temp dir ---
$tmp = Join-Path $env:TEMP "methodman-tests-$(Get-Random)"
New-Item -Path $tmp -ItemType Directory -Force | Out-Null

$pass = 0
$fail = 0

function Write-Pass($msg) {
    Write-Host "  [PASS] $msg" -ForegroundColor Green
    $script:pass++
}

function Write-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:fail++
}

function Write-Section($msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

try {
    # --- Copy files to tmp ---
    Copy-Item (Join-Path $repo "mask.ps1") (Join-Path $tmp "mask.ps1") -Force
    Copy-Item (Join-Path $fixtures "masking-dict.test.ps1") (Join-Path $tmp "masking-dict.test.ps1") -Force
    Copy-Item ((Join-Path (Join-Path $fixtures "input") "sample.md")) (Join-Path $tmp "sample.md") -Force

    # --- Test 1: first run ---
    Write-Section "Test 1: mask.ps1 first run"

    Push-Location $tmp
    try {
        $output = & ".\mask.ps1" -DictPath "masking-dict.test.ps1" 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($exitCode -eq 0 -or $null -eq $exitCode) {
        Write-Pass "mask.ps1 exited cleanly"
    } else {
        Write-Fail "mask.ps1 exited with code $exitCode"
    }

    # --- Test 2: compare with expected ---
    Write-Section "Test 2: output matches expected/sample.md"

    $actualPath = Join-Path $tmp "sample.md"
    $expectedPath = (Join-Path (Join-Path $fixtures "expected") "sample.md")

    $actualBytes = [System.IO.File]::ReadAllBytes($actualPath)
    $expectedBytes = [System.IO.File]::ReadAllBytes($expectedPath)

    if ($actualBytes.Length -ne $expectedBytes.Length) {
        Write-Fail "byte length differs: actual=$($actualBytes.Length) expected=$($expectedBytes.Length)"
    } else {
        $diffAt = -1
        for ($i = 0; $i -lt $actualBytes.Length; $i++) {
            if ($actualBytes[$i] -ne $expectedBytes[$i]) {
                $diffAt = $i
                break
            }
        }
        if ($diffAt -eq -1) {
            Write-Pass "byte-for-byte identical to expected/sample.md"
        } else {
            Write-Fail "first byte diff at position $diffAt"
            $actualLines = [System.IO.File]::ReadAllLines($actualPath, [System.Text.Encoding]::UTF8)
            $expectedLines = [System.IO.File]::ReadAllLines($expectedPath, [System.Text.Encoding]::UTF8)
            $maxLines = [Math]::Max($actualLines.Length, $expectedLines.Length)
            $shown = 0
            for ($i = 0; $i -lt $maxLines -and $shown -lt 5; $i++) {
                $a = if ($i -lt $actualLines.Length) { $actualLines[$i] } else { "<MISSING>" }
                $e = if ($i -lt $expectedLines.Length) { $expectedLines[$i] } else { "<MISSING>" }
                if ($a -ne $e) {
                    Write-Host "    line $($i):"
                    Write-Host "      actual:   $a"
                    Write-Host "      expected: $e"
                    $shown++
                }
            }
        }
    }

    # --- Test 3: idempotency ---
    Write-Section "Test 3: mask.ps1 idempotency"

    $hashBefore = (Get-FileHash -Path $actualPath -Algorithm SHA256).Hash

    Push-Location $tmp
    try {
        & ".\mask.ps1" -DictPath "masking-dict.test.ps1" 2>&1 | Out-Null
    } finally {
        Pop-Location
    }

    $hashAfter = (Get-FileHash -Path $actualPath -Algorithm SHA256).Hash

    if ($hashBefore -eq $hashAfter) {
        Write-Pass "second run did not change the file (idempotent)"
    } else {
        Write-Fail "second run changed the file (NOT idempotent)"
        Write-Host "    hash before: $hashBefore"
        Write-Host "    hash after:  $hashAfter"
    }

} finally {
    # --- Cleanup ---
    if (Test-Path $tmp) {
        Remove-Item $tmp -Recurse -Force
    }
}

# --- Summary ---
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  TESTS COMPLETE" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($fail -eq 0) {
    Write-Host "  ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "  TESTS FAILED" -ForegroundColor Red
    exit 1
}
