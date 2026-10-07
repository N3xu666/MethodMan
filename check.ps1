# check.ps1
# Проверка репозитория на утечки и артефакты.
# Требует masking-dict.ps1 в той же директории.
# Использование: .\check.ps1

$ErrorActionPreference = "Stop"
$repo = "C:\Users\Irshad\Documents\GitHub\MethodMan"
Set-Location $repo

$dictPath = Join-Path $repo "masking-dict.ps1"
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8 = [System.Text.Encoding]::UTF8
$totalIssues = 0

# Файлы-не-walkthrough, которые не должны содержать Note
$excluded = @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md')

# ============================================================
# 1. Реальные 32-hex флаги
# ============================================================
Write-Host "`n=== [1/6] Real 32-hex flags ===" -ForegroundColor Cyan
$flags = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' } |
  ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flags += [regex]::Matches($c, "\b[a-fA-F0-9]{32}\b").Count
  }
if ($flags -eq 0) { Write-Host "OK: 0 flags" -ForegroundColor Green }
else { Write-Host "FAIL: $flags flags left" -ForegroundColor Red; $totalIssues += $flags }

# ============================================================
# 2. Реальные пароли/хеши/ключи из словаря
# ============================================================
Write-Host "`n=== [2/6] Real passwords/hashes/keys from dict ===" -ForegroundColor Cyan
$leaks = 0
foreach ($key in $replacements.Keys) {
    if ($key -match '^<.*>$') { continue }
    if ($key -match '^[a-fA-F0-9]{32}$') { continue }
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
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
# 3. Note после Attack Chain (только walkthrough)
# ============================================================
Write-Host "`n=== [3/6] Ethical note in walkthroughs ===" -ForegroundColor Cyan
$withNote = 0
$withoutNote = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    if ($c -match "have been masked for ethical reasons") { $withNote++ }
    else { Write-Host "  MISSING NOTE: $($_.Name)" -ForegroundColor Yellow; $withoutNote++ }
  }
Write-Host "Files with note: $withNote"
Write-Host "Files without note: $withoutNote"
if ($withoutNote -gt 0) { $totalIssues += $withoutNote }

# ============================================================
# 4. Длинные тире
# ============================================================
Write-Host "`n=== [4/6] Long dashes ===" -ForegroundColor Cyan
$d = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $d += [regex]::Matches($c, "[\u2013\u2014\u2212]").Count
      }
}
if ($d -eq 0) { Write-Host "OK: 0 dashes" -ForegroundColor Green }
else { Write-Host "FAIL: $d long dashes" -ForegroundColor Red; $totalIssues += $d }

# ============================================================
# 5. Битые символы
# ============================================================
Write-Host "`n=== [5/6] Broken chars (U+FFFD) ===" -ForegroundColor Cyan
$b = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $b += [regex]::Matches($c, "[\uFFFD]").Count
      }
}
if ($b -eq 0) { Write-Host "OK: 0 broken chars" -ForegroundColor Green }
else { Write-Host "FAIL: $b broken chars" -ForegroundColor Red; $totalIssues += $b }

# ============================================================
# 6. Артефакты маскировки
# ============================================================
Write-Host "`n=== [6/6] Masking artifacts ===" -ForegroundColor Cyan
$artifacts = @('<PASSWORD>blog', '<PASSWORD>.htb', '<USER_FLAG>FLAG', '<ROOT_FLAG>FLAG')
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
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
# Итог
# ============================================================
Write-Host "`n============================================" -ForegroundColor Cyan
if ($totalIssues -eq 0) {
    Write-Host "ALL CHECKS PASSED - ready to commit + push" -ForegroundColor Green
} else {
    Write-Host "TOTAL ISSUES: $totalIssues - fix before push" -ForegroundColor Red
    exit 1
}
Write-Host "============================================" -ForegroundColor Cyan
