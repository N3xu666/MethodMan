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

param(
    [string]$DictPath = 'masking-dict.ps1'
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

$dictPath = Join-Path $repo $DictPath
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8 = [System.Text.Encoding]::UTF8
$totalIssues = 0

# Stub markers (active machines - placeholder files)
$stubMarkers = @(
    'Status: Completed',      # En
    'Status: Пройдено',        # Ru (English prefix)
    'Статус: Пройдено',        # Ru (native prefix)
    'Status: Tamamlandı'      # Az
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
$excluded = @('_WORKFLOW.md', 'masking-dict.ps1', '_SITE_PLAN.md')
# Files that are not walkthroughs (no Note, no Attack Chain)
$notWalkthrough = @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'OSCP-Reporting.md', '_WORKFLOW.md', 'masking-dict.ps1', 'SECURITY.md', '_SITE_PLAN.md')

# ============================================================
# 1. Real 32-hex flags
# ============================================================
Write-Host "`n=== [1/16] Real 32-hex flags ===" -ForegroundColor Cyan
$flags = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flags += [regex]::Matches($c, "\b[a-fA-F0-9]{32}\b").Count
  }
if ($flags -eq 0) { Write-Host "OK: 0 flags" -ForegroundColor Green }
else { Write-Host "FAIL: $flags flags left" -ForegroundColor Red; $totalIssues += $flags }

# ============================================================
# 2. Real passwords/hashes/keys from dictionary
# ============================================================
Write-Host "`n=== [2/16] Real passwords/hashes/keys from dict ===" -ForegroundColor Cyan
$leaks = 0
foreach ($key in $replacements.Keys) {
    if ($key -match '^<.*>$') { continue }
    if ($key -match '^[a-fA-F0-9]{32}$') { continue }
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
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
Write-Host "`n=== [3/16] Ethical note in walkthroughs ===" -ForegroundColor Cyan
$withNote = 0
$withoutNote = 0
$stubCount = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $notWalkthrough } |
  ForEach-Object {
    if (Test-StubFile $_.FullName) {
        $stubCount++
    } else {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $noteTexts = @(
            'All flags, passwords, hashes, and session tokens have been masked for ethical reasons',
            'Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям',
            'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir'
        )
        $hasNote = $false
        foreach ($nt in $noteTexts) { if ($c.Contains($nt)) { $hasNote = $true; break } }
        if ($hasNote) { $withNote++ }
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
Write-Host "`n=== [4/16] Long dashes ===" -ForegroundColor Cyan
$d = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
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
Write-Host "`n=== [5/16] Broken chars (U+FFFD) ===" -ForegroundColor Cyan
$b = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
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
Write-Host "`n=== [6/16] Masking artifacts ===" -ForegroundColor Cyan
$artifacts = @('<PASSWORD>blog', '<PASSWORD>.htb', '<USER_FLAG>FLAG', '<ROOT_FLAG>FLAG')
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
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
Write-Host "`n=== [7/16] Heuristic: suspicious passwords (WARN only) ===" -ForegroundColor Cyan
$suspicious = @()
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $mm = [regex]::Matches($ct, '(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[:=]\s*([^\s`<>]{5,})')
    foreach ($x in $mm) {
        $val = $x.Groups[2].Value
        if ($val -match '^<.*>$') { continue }
        if ($val -match '^\$2[aby]\$' -or $val -match '^\*?[A-F0-9]{32,}$') { continue }
        # P1.1: skip sudo directives and path segments (PASSWD: /usr/bin/wget)
if ($val -match '^[/\\]') { continue }
if ($val -match '^\.') { continue }
# P1.1: skip Hydra placeholders (^PASS^, ^USER^)
if ($val -match '\^') { continue }
# P1.1: skip ALL_CAPS identifiers (env var refs, constants)
if ($val -match '^[A-Z_]{3,5}$') { continue }
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

# ============================================================
# 8. CVE reference in Exploitation (WARN only, does not block)
# ============================================================
Write-Host "`n=== [8/16] CVE reference in Exploitation (WARN only) ===" -ForegroundColor Cyan
$missingCve = @()
$checkedExpl = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.Name -notin $notWalkthrough } |
  ForEach-Object {
    if (Test-StubFile $_.FullName) { return }
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $lines2 = $ct -split "`n"
    $explText = ""
    $inCode = $false
    foreach ($ln in $lines2) {
        if ($ln -match '^```') { $inCode = -not $inCode; continue }
        if (-not $inCode) { $explText += $ln + "`n" }
    }
    $script:checkedExpl++
    $hasCve = ($explText -match 'CVE-\d{4}-\d{4,}')
    $hasNoCve = ($explText -match 'No CVE \(custom vulnerability\)')
    if (-not $hasCve -and -not $hasNoCve) {
        $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
        $script:missingCve += $rel
    }
  }
if ($missingCve.Count -eq 0) {
    Write-Host "OK: all Exploitation sections have a CVE reference ($checkedExpl checked)" -ForegroundColor Green
} else {
    Write-Host "WARN: $($missingCve.Count) Exploitation section(s) without CVE reference:" -ForegroundColor Yellow
    $missingCve | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($missingCve.Count -gt 10) { Write-Host "  ... and $($missingCve.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# 9. Unreplaced placeholders in docs (FAIL)
# Scans: APPLICATIONS/01 Web/**, methodology/**, root *.md (README, CHEATSHEET,
# METHODOLOGY, SECURITY). Looks for %%XX%% style markers.
# ============================================================
Write-Host "`n=== [9/16] Unreplaced placeholders in docs ===" -ForegroundColor Cyan
$docRootFiles = @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'SECURITY.md')
$placeholderCount = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object {
    $_.FullName -notmatch '\\\.git\\' -and
    $_.FullName -notmatch '\\txt\\' -and
    $_.FullName -notmatch '\\tests\\' -and
    $_.FullName -notmatch '\\tools\\' -and
    ($_.FullName -match '\\APPLICATIONS\\' -or $_.FullName -match '\\INFRASTRUCTURE\\' -or $_.FullName -match '\\ANONYMITY-PRIVACY-OPSEC\\' -or $_.FullName -match '\\AI\\' -or $_.FullName -match '\\methodology\\' -or $_.Name -in $docRootFiles)
  } |
  ForEach-Object {
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $matches = [regex]::Matches($ct, '%%[A-Z0-9]+%%')
    if ($matches.Count -gt 0) {
      $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
      $unique = ($matches | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ', '
      Write-Host "  PLACEHOLDER: $rel ($($matches.Count) markers: $unique)" -ForegroundColor Red
      $script:placeholderCount += $matches.Count
    }
  }
if ($placeholderCount -eq 0) { Write-Host "OK: 0 unreplaced placeholders in docs" -ForegroundColor Green }
else { Write-Host "FAIL: $placeholderCount unreplaced placeholders" -ForegroundColor Red; $totalIssues += $placeholderCount }

# ============================================================
# 10. Broken relative links in docs (WARN only, does not block)
# Scans: APPLICATIONS/01 Web/**/*.md, methodology/**/*.md, root *.md. Skips code blocks, anchors, http(s)/mailto.
# ============================================================
Write-Host "`n=== [10/16] Broken relative links in docs (WARN only) ===" -ForegroundColor Cyan
$brokenLinks = @()
$linkExcludeNames = @('_WORKFLOW.md', '_SITE_PLAN.md', 'PROMPT_NEXT_SESSION.txt')
$linkFiles = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\\\\.git\\\\' -and
    $_.FullName -notmatch '\\\\txt\\\\' -and
    $_.FullName -notmatch '\\\\tests\\\\' -and
    $_.Name -notin $linkExcludeNames
  }
$linkFiles |
  ForEach-Object {
    $f = $_
    $dir = $f.Directory.FullName
    $ln = 0
    $inCode = $false
    Get-Content -Path $f.FullName | ForEach-Object {
      $ln++
      $line = $_
      if ($line -match '^```') { $inCode = -not $inCode; return }
      if ($inCode) { return }
      [regex]::Matches($line, '\]\(([^)]+)\)') | ForEach-Object {
        $link = $_.Groups[1].Value.Trim()
        if ($link -match '^https?:' -or $link -match '^mailto:' -or $link -match '^#') { return }
        $noAnchor = ($link -split '#')[0]
        if ($noAnchor -eq '') { return }
        $decoded = [System.Uri]::UnescapeDataString($noAnchor)
        $combined = Join-Path $dir $decoded
        try { $target = [System.IO.Path]::GetFullPath($combined) } catch { return }
        if (-not (Test-Path $target)) {
          $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
          $script:brokenLinks += "${rel}:${ln}: $link"
        }
      }
    }
  }
if ($brokenLinks.Count -eq 0) { Write-Host "OK: 0 broken relative links across all tracked .md" -ForegroundColor Green }
else {
  Write-Host "WARN: $($brokenLinks.Count) broken relative link(s):" -ForegroundColor Yellow
  $brokenLinks | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($brokenLinks.Count -gt 10) { Write-Host "  ... and $($brokenLinks.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# 11. Counter consistency in root README (WARN only, does not block)
# Compares root README counter with actual file counts.
# ============================================================
Write-Host "`n=== [11/16] Counter consistency in root README (WARN only) ===" -ForegroundColor Cyan
$counterWarn = 0

# Count published (non-stub) and stubs in all 01 Az/ folders
$publishedTotal = 0
$stubsTotal = 0
$categories = Get-ChildItem -Recurse -Directory -Filter "01 Az" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\tests\\' }
foreach ($cat in $categories) {
    $files = Get-ChildItem -Path $cat.FullName -Filter *.md -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if (Test-StubFile $f.FullName) { $stubsTotal++ } else { $publishedTotal++ }
    }
}

# Read root README counter
$readmePath = Join-Path $repo "README.md"
if (Test-Path $readmePath) {
    $readmeContent = [System.IO.File]::ReadAllText($readmePath, $utf8)
    $counterMatch = [regex]::Match($readmeContent, 'Currently:\s+\*\*(\d+)\s+published.*?\+\s+(\d+)\s+active stubs\*\*\s+=\s+\*\*(\d+)\s+completed')
    if ($counterMatch.Success) {
        $readmePub = [int]$counterMatch.Groups[1].Value
        $readmeStub = [int]$counterMatch.Groups[2].Value
        $readmeTotal = [int]$counterMatch.Groups[3].Value
        if ($readmePub -ne $publishedTotal) {
            Write-Host "WARN: README published=$readmePub, actual=$publishedTotal" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($readmeStub -ne $stubsTotal) {
            Write-Host "WARN: README stubs=$readmeStub, actual=$stubsTotal" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($readmeTotal -ne ($readmePub + $readmeStub)) {
            Write-Host "WARN: README total=$readmeTotal, sum=$($readmePub + $readmeStub)" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($counterWarn -eq 0) {
            Write-Host "OK: README counter matches actual ($publishedTotal published + $stubsTotal stubs)" -ForegroundColor Green
        }
    } else {
        Write-Host "WARN: root README counter pattern not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARN: root README.md not found" -ForegroundColor Yellow
}

# ============================================================
# 12. CVE version ranges in docs tables (WARN only, does not block)
# Scans APPLICATIONS/01 Web/** for table rows that reference a CVE and an NVD/MITRE
# link but contain no version range (no digit outside the CVE ID).
# References lists (`- CVE-...: url`) are skipped on purpose.
# ============================================================
Write-Host "`n=== [12/16] CVE version ranges in docs tables (WARN only) ===" -ForegroundColor Cyan
$bareCve = @()
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -match '\\APPLICATIONS\\' -or $_.FullName -match '\\INFRASTRUCTURE\\' -or $_.FullName -match '\\ANONYMITY-PRIVACY-OPSEC\\' -or $_.FullName -match '\\AI\\' } |
  ForEach-Object {
    $lines3 = [System.IO.File]::ReadAllLines($_.FullName, $utf8)
    for ($i = 0; $i -lt $lines3.Count; $i++) {
      $ln = $lines3[$i]
      if ($ln -notmatch '^\|\s*CVE-\d{4}-\d{4,}') { continue }
      if ($ln -notmatch 'nvd\.nist\.gov|cve\.mitre\.org') { continue }
      $cells = $ln.Split('|') | ForEach-Object { $_.Trim() }
      $hasVersion = $false
      foreach ($c in $cells) {
        if ($c -eq '') { continue }
        if ($c -match 'CVE-\d{4}') { continue }
        if ($c -match 'nvd\.nist\.gov') { continue }
        if ($c -match 'cve\.mitre\.org') { continue }
        if ($c -match '^https?://') { continue }
        if ($c -match '\d') { $hasVersion = $true; break }
      }
      if (-not $hasVersion) {
        $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
        $script:bareCve += "${rel}:$($i+1): $($ln.Trim())"
      }
    }
  }
if ($bareCve.Count -eq 0) {
  Write-Host "OK: all CVE table rows include a version range" -ForegroundColor Green
} else {
  Write-Host "WARN: $($bareCve.Count) CVE table row(s) without version range (manual review):" -ForegroundColor Yellow
  $bareCve | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($bareCve.Count -gt 10) { Write-Host "  ... and $($bareCve.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# ============================================================
# [13/16] Backslash escapes in docs (FAIL)
# ============================================================
Write-Host "`n=== [13/16] Backslash escapes in docs ===" -ForegroundColor Cyan
$bsEscapes = @()
$docsRoots = @('APPLICATIONS', 'INFRASTRUCTURE', 'ANONYMITY-PRIVACY-OPSEC', 'AI', 'tools')
$docsFiles = @()
foreach ($root in $docsRoots) {
    $p = Join-Path $repo $root
    if (Test-Path $p) {
        $docsFiles += Get-ChildItem -Path $p -Recurse -File -Filter '*.md' -ErrorAction SilentlyContinue
    }
}
$docsFiles += Get-ChildItem -Path $repo -File -Filter '*.md' -ErrorAction SilentlyContinue
$bsPattern = '^\\[#\[\]_()]'
foreach ($f in $docsFiles) {
    if ($f.FullName -match '\\\.git\\' -or $f.FullName -match '\\txt\\' -or $f.FullName -match '\\tests\\') { continue }
    $lines = [System.IO.File]::ReadAllLines($f.FullName, $utf8)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ($ln -match $bsPattern) {
            $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
            $bsEscapes += "${rel}:$($i+1): $($ln.Trim())"
        }
    }
}
if ($bsEscapes.Count -eq 0) {
    Write-Host "OK: 0 backslash-escaped markdown headers/links" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($bsEscapes.Count) line(s) with backslash-escaped markdown (unreplaced placeholders):" -ForegroundColor Red
    $bsEscapes | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($bsEscapes.Count -gt 10) { Write-Host "  ... and $($bsEscapes.Count - 10) more" -ForegroundColor Gray }
    $totalIssues += $bsEscapes.Count
}
# ============================================================
# [14/16] Stale references in tracked .md (WARN only)
# Detects old folder names / marketing phrases left after
# restructures. Any occurrence is a signal to update the file.
# ============================================================
Write-Host "`n=== [14/16] Stale references (WARN only) ===" -ForegroundColor Cyan
$stalePhrases = @('02 Web', '01 HTB', 'OSCP-grade')
$staleHits = @()
$staleFiles = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\\\\.git\\\\' -and
    $_.FullName -notmatch '\\\\txt\\\\' -and
    $_.FullName -notmatch '\\\\tests\\\\' -and
    $_.Name -notin @('_WORKFLOW.md', '_SITE_PLAN.md', 'PROMPT_NEXT_SESSION.txt')
  }
foreach ($f in $staleFiles) {
  $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
  $ln = 0
  foreach ($line in ($ct -split "`n")) {
    $ln++
    foreach ($ph in $stalePhrases) {
      if ($line.Contains($ph)) {
        $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
        $staleHits += "${rel}:${ln}: [$ph] $($line.Trim())"
      }
    }
  }
}
if ($staleHits.Count -eq 0) {
  Write-Host "OK: 0 stale references (02 Web / 01 HTB / OSCP-grade)" -ForegroundColor Green
} else {
  Write-Host "WARN: $($staleHits.Count) stale reference(s) - review:" -ForegroundColor Yellow
  $staleHits | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($staleHits.Count -gt 10) { Write-Host "  ... and $($staleHits.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# [15/16] Language counter marker consistency (WARN only)
# Every "(N <marker> 3 languages)" line in WRITEUPS/**/README.md
# must use the multiplication sign U+00D7 between the number and
# "3 languages". Latin "x", "X", "*", "-", or mojibake "G-" are
# cosmetic drift (pass 71) and must be fixed.
# ============================================================
Write-Host "`n=== [15/16] Language counter marker (WARN only) ===" -ForegroundColor Cyan
$timesSign = [string][char]0x00D7
$counterWarns = @()
$counterFiles = Get-ChildItem -Path (Join-Path $repo "WRITEUPS") -Recurse -Filter "README.md" -ErrorAction SilentlyContinue
foreach ($f in $counterFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $ln = 0
    foreach ($line in ($ct -split "`n")) {
        $ln++
        $ms = [regex]::Matches($line, '\((\S+)\s+3 languages\)')
        foreach ($m in $ms) {
            $marker = $m.Groups[1].Value
            if ($marker -ne $timesSign) {
                $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
                $counterWarns += "${rel}:${ln}: marker='$marker' (expected U+00D7)"
            }
        }
    }
}
if ($counterWarns.Count -eq 0) {
    Write-Host "OK: all language counters use U+00D7" -ForegroundColor Green
} else {
    Write-Host "WARN: $($counterWarns.Count) language counter(s) with wrong marker - review:" -ForegroundColor Yellow
    $counterWarns | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($counterWarns.Count -gt 10) { Write-Host "  ... and $($counterWarns.Count - 10) more" -ForegroundColor Gray }
}
# ============================================================
Write-Host "`n=== [16/16] Chat citation markers (FAIL) ===" -ForegroundColor Cyan
$citationFiles = Get-ChildItem -Path $repo -Recurse -Filter "*.md" -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\txt\\' -and
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '\\tests\\' -and
        $_.FullName -notmatch '_WORKFLOW'
    }
$citationHits = @()
foreach ($f in $citationFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $m = [regex]::Matches($ct, 'citation:\d+')
    if ($m.Count -gt 0) {
        $rel = $f.FullName.Replace($repo + '\', '')
        $citationHits += "$rel ($($m.Count))"
    }
}
if ($citationHits.Count -eq 0) {
    Write-Host "OK: 0 citation markers" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($citationHits.Count) files contain chat citation markers:" -ForegroundColor Red
    $citationHits | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $totalIssues++
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
    exit 0
} else {
    Write-Host "TOTAL ISSUES: $totalIssues - fix before push" -ForegroundColor Red
    exit 1
}
Write-Host "============================================" -ForegroundColor Cyan
