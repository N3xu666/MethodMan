# check.ps1
# Repository check: leaks and artifacts.
# Requires masking-dict.ps1 in the same directory.
# Usage: .\check.ps1
#
# Stub detection:
#   Files whose first 15 lines contain a "Status: **Completed**" marker
#   (any language: En/Ru/Az) are treated as stubs (active machines) and
#   excluded from the "Ethical note in walkthroughs" check.
#   All other checks (flags, leaks, dashes, chars, artifacts, heuristic)
#   still apply to stub files.
#
# The txt/ directory (drafts, .gitignore) is excluded from all checks.

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

$dictPath = Join-Path $repo "masking-dict.ps1"
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8 = [System.Text.Encoding]::UTF8
$totalIssues = 0

# Stub markers (active machines - placeholder files)
$stubMarkers = @(
    'Status: **Completed**',      # En
    'Status: **Пройдено**',        # Ru (English prefix)
    'Статус: **Пройдено**',        # Ru (native prefix)
    'Status: **Tamamlandı**'      # Az
)

function Test-StubFile([string]$filePath) {
    try {
        $head = Get-Content -Path $filePath -TotalCount 15 -ErrorAction Stop
        foreach ($line in $head) {
            foreach ($marker in $stubMarkers) {
                if ($line -like "*$marker*") { return $true }
            }
        }
    } catch {
        return $false
    }
    return $false
}

# Not-published files (skip in all content checks)
$excluded = @('_WORKFLOW.md', 'masking-dict.ps1')
# Files that are not walkthroughs (no Note, no Attack Chain)
$notWalkthrough = @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', '_WORKFLOW.md', 'masking-dict.ps1')

# ============================================================
# 1. Real 32-hex flags
# ============================================================
Write-Host "`n=== [1/7] Real 32-hex flags ===" -ForegroundColor Cyan
$flags = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flags += [regex]::Matches($c, "\b[a-fA-F0-9]{32}\b").Count
  }
if ($flags -eq 0) { Write-Host "OK: 0 flags" -ForegroundColor Green }
else { Write-Host "FAIL: $flags flags left" -ForegroundColor Red; $totalIssues += $flags }

# ============================================================
# 2. Real passwords/hashes/keys from dictionary
# ============================================================
Write-Host "`n=== [2/7] Real passwords/hashes/keys from dict ===" -ForegroundColor Cyan
$leaks = 0
foreach ($key in $replacements.Keys) {
    if ($key -match '^<.*>$') { continue }
    if ($key -match '^[a-fA-F0-9]{32}$') { continue }
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($key))).Count
      }
    if ($count -gt 0) {
        Write-Host ("  LEAK: '{0}' x{1}" -f $key, $count) -ForegroundColor Red
        $leaks += $count
    }
}
if ($leaks -eq 0) { Write-Host "OK: 0 leaks" -ForegroundColor Green }
else { Write-Host "FAIL: $leaks leaks" -ForegroundColor Red; $totalIssues += $leaks }

# ============================================================
# 3. Note after Attack Chain (walkthroughs only, skip stubs)
# ============================================================
Write-Host "`n=== [3/7] Ethical note in walkthroughs ===" -ForegroundColor Cyan
$withNote = 0
$withoutNote = 0
$stubCount = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $notWalkthrough } |
  ForEach-Object {
    if (Test-StubFile $_.FullName) {
        $stubCount++
    } else {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        if ($c -match "have been masked for ethical reasons" -or $c -match "etik səbəblərə görə maskalanmışdır") { $withNote++ }
        else { Write-Host "  MISSING NOTE: $($_.Name)" -ForegroundColor Yellow; $withoutNote++ }
    }
  }
Write-Host "Files with note: $withNote"
Write-Host "Files without note: $withoutNote"
Write-Host "Stub files skipped: $stubCount" -ForegroundColor Gray
if ($withoutNote -gt 0) { $totalIssues += $withoutNote }

# ============================================================
# 4. Long dashes
# ============================================================
Write-Host "`n=== [4/7] Long dashes ===" -ForegroundColor Cyan
$d = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $d += [regex]::Matches($c, "[\u2013\u2014\u2212]").Count
      }
}
if ($d -eq 0) { Write-Host "OK: 0 dashes" -ForegroundColor Green }
else { Write-Host "FAIL: $d long dashes" -ForegroundColor Red; $totalIssues += $d }

# ============================================================
# 5. Broken chars
# ============================================================
Write-Host "`n=== [5/7] Broken chars (U+FFFD) ===" -ForegroundColor Cyan
$b = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $b += [regex]::Matches($c, "[\uFFFD]").Count
      }
}
if ($b -eq 0) { Write-Host "OK: 0 broken chars" -ForegroundColor Green }
else { Write-Host "FAIL: $b broken chars" -ForegroundColor Red; $totalIssues += $b }

# ============================================================
# 6. Masking artifacts
# ============================================================
Write-Host "`n=== [6/7] Masking artifacts ===" -ForegroundColor Cyan
$artifacts = @('<PASSWORD>blog', '<PASSWORD>.htb', '<USER_FLAG>FLAG', '<ROOT_FLAG>FLAG')
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($art))).Count
      }
    if ($count -gt 0) {
        Write-Host ("  ARTIFACT: '{0}' x{1}" -f $art, $count) -ForegroundColor Red
        $a += $count
    }
}
if ($a -eq 0) { Write-Host "OK: 0 artifacts" -ForegroundColor Green }
else { Write-Host "FAIL: $a artifacts" -ForegroundColor Red; $totalIssues += $a }

# ============================================================
# 7. Heuristic: possibly unmasked secrets (WARN only, does not block)
# ============================================================
Write-Host "`n=== [7/7] Heuristic: suspicious passwords (WARN only) ===" -ForegroundColor Cyan
$suspicious = @()
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $mm = [regex]::Matches($ct, '(?i)(password|passwd|pwd)\s*[:=]\s*([^\s`<>]{5,})')
    foreach ($x in $mm) {
        $val = $x.Groups[2].Value
        if ($val -match '^<.*>$') { continue }
        if ($val -match '^\$2[aby]\$' -or $val -match '^\*?[A-F0-9]{32,}$') { continue }
        if ($val -match '^(password|null|none|undefined|example|test|changeme|N/A)$') { continue }
        $suspicious += "$($_.Name): $($x.Value)"
    }
  }
if ($suspicious.Count -eq 0) {
    Write-Host "OK: 0 suspicious (all matches look masked or benign)" -ForegroundColor Green
} else {
    Write-Host "WARN: $($suspicious.Count) possible unmasked secrets (manual review):" -ForegroundColor Yellow
    $suspicious | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($suspicious.Count -gt 10) { Write-Host "  ... and $($suspicious.Count - 10) more" -ForegroundColor Gray }
}

# Summary
# ============================================================
Write-Host "`n============================================" -ForegroundColor Cyan
if ($totalIssues -eq 0) {
    Write-Host "ALL CHECKS PASSED - ready to commit + push" -ForegroundColor Green
    Write-Host ""
    Write-Host "  REMINDER before committing a NEW walkthrough:" -ForegroundColor Magenta
    Write-Host "    1. Add new real secrets to masking-dict.ps1 (passwords, flags, hashes)." -ForegroundColor Magenta
    Write-Host "    2. Run .\update-readmes.ps1 to refresh README tables and counters." -ForegroundColor Magenta
} else {
    Write-Host "TOTAL ISSUES: $totalIssues - fix before push" -ForegroundColor Red
    exit 1
}
Write-Host "============================================" -ForegroundColor Cyan