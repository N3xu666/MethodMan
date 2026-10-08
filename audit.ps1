# ============================================================
# FINAL AUDIT v3 - MethodMan
# ============================================================
# Changes vs v2:
#   - No hardcoded "45 walkthroughs" - counts dynamically.
#   - New section [21]: language pairs per category.
#   - New section [22]: summary (N machines x 3 languages).
#   - All other checks unchanged.
# ============================================================

cd $PSScriptRoot

$utf8 = [System.Text.Encoding]::UTF8
$script:pass = 0
$script:fail = 0
$script:warn = 0

function Write-Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $script:pass++ }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:fail++ }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:warn++ }
function Write-Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     FINAL AUDIT v3 - MethodMan" -ForegroundColor Cyan
Write-Host "     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. GIT STATE
Write-Host "`n[1] Git state" -ForegroundColor Yellow
$status = git status --short
if (-not $status) { Write-Pass "working tree clean" } else { Write-Fail "working tree dirty" }
Write-Info "last 5 commits:"
git log -5 --oneline | ForEach-Object { Write-Info "    $_" }
$remote = git remote get-url origin 2>$null
if ($remote) { Write-Pass "remote: $remote" } else { Write-Fail "no remote origin" }
$local = git rev-parse HEAD 2>$null
$upstream = git rev-parse '@{u}' 2>$null
if ($local -and $upstream -and $local -eq $upstream) { Write-Pass "local == origin/main (pushed)" } else { Write-Fail "local != origin/main" }

# 2. FILES IN ROOT
Write-Host "`n[2] Files in root" -ForegroundColor Yellow
Get-ChildItem -Force | Where-Object { $_.Name -ne '.git' } | Select-Object Name, Length | Format-Table -AutoSize

# 3. GITIGNORE
Write-Host "[3] .gitignore" -ForegroundColor Yellow
$gitignoreContent = Get-Content ".gitignore" -ErrorAction SilentlyContinue
if ($gitignoreContent) { Write-Pass ".gitignore exists" } else { Write-Fail ".gitignore missing" }
$mustIgnore = @('masking-dict.ps1', '_WORKFLOW.md', 'update-readmes.ps1', 'txt/')
foreach ($f in $mustIgnore) {
    $checkPath = if ($f -eq 'txt/') { "01 HTB/02 OSCP/01 Linux/txt/ru/01 Sea.txt" } else { $f }
    $ignored = git check-ignore $checkPath 2>$null
    if ($ignored) { Write-Pass "$f is ignored" } else { Write-Fail "$f NOT ignored" }
}

# 4. TRACKED FILES
Write-Host "`n[4] Tracked files" -ForegroundColor Yellow
$trackedMd = git ls-files "*.md"
Write-Pass "tracked .md: $($trackedMd.Count)"
$trackedPs1 = git ls-files "*.ps1"
Write-Info "tracked .ps1 ($($trackedPs1.Count)):"
$trackedPs1 | ForEach-Object { Write-Info "    $_" }
$trackedTxt = git ls-files "*.txt"
if ($trackedTxt.Count -eq 0) { Write-Pass "0 tracked .txt" } else { Write-Warn "$($trackedTxt.Count) tracked .txt" }

# 5. UNTRACKED FILES
Write-Host "`n[5] Untracked files" -ForegroundColor Yellow
$untracked = git ls-files --others --exclude-standard
if (-not $untracked) { Write-Pass "no untracked files" } else { Write-Warn "untracked files:"; $untracked | ForEach-Object { Write-Info "    $_" } }

# 6. WALKTHROUGHS (DYNAMIC COUNT)
Write-Host "`n[6] Walkthroughs" -ForegroundColor Yellow
$walkthroughs = Get-ChildItem -Recurse -Filter *.md -Path "01 HTB" | Where-Object { $_.FullName -match '\\0[123] (Az|En|Ru)\\' }
Write-Info "found $($walkthroughs.Count) walkthrough files"
if ($walkthroughs.Count % 3 -eq 0) {
    $machineCount = $walkthroughs.Count / 3
    Write-Pass "$($walkthroughs.Count) walkthroughs = $machineCount machines x 3 languages"
} else {
    Write-Fail "$($walkthroughs.Count) walkthroughs is NOT divisible by 3"
}

# 7. WALKTHROUGH STRUCTURE
Write-Host "`n[7] Walkthrough structure" -ForegroundColor Yellow
$badStructure = @()
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    $hasHeader = $c -match '(?m)^#\s+.+\s+\(HTB\)'
    $hasBlockquote = ([regex]::Matches($c, '(?m)^>\s*\S+:').Count) -ge 3
    if (-not ($hasHeader -and $hasBlockquote)) { $badStructure += $wt.Name }
}
if ($badStructure.Count -eq 0) { Write-Pass "all walkthroughs have valid headers" } else { Write-Fail "walkthroughs with broken headers:"; $badStructure | ForEach-Object { Write-Info "    $_" } }

# 8. ATTACK CHAIN
Write-Host "`n[8] Attack Chain" -ForegroundColor Yellow
$noAttackChain = @()
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    if (-not ($c -match '(?m)^##\s+(Attack Chain|Hücum Zənciri)')) { $noAttackChain += $wt.Name }
}
if ($noAttackChain.Count -eq 0) { Write-Pass "all walkthroughs have Attack Chain" } else { Write-Fail "missing Attack Chain:"; $noAttackChain | ForEach-Object { Write-Info "    $_" } }

# 9. NOTE PLACEMENT
Write-Host "`n[9] Ethical note placement" -ForegroundColor Yellow
$badNote = @()
$noteText = '(have been masked for ethical reasons|etik səbəblərə görə maskalanmışdır)'
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    if ($c -notmatch $noteText) { $badNote += "$($wt.Name) - MISSING"; continue }
    $pattern = '(?s)(```text.*?```)\s*(>\s*(?:Note|Qeyd):[^\r\n]*(?:have been masked|etik səbəblərə görə maskalanmışdır)[^\r\n]*)\s*\r?\n\s*---'
    if ($c -notmatch $pattern) { $badNote += "$($wt.Name) - wrong position" }
}
if ($badNote.Count -eq 0) { Write-Pass "all walkthroughs: Note right after Attack Chain" } else { Write-Fail "Note issues:"; $badNote | ForEach-Object { Write-Info "    $_" } }

# 10. REAL 32-HEX FLAGS
Write-Host "`n[10] Real 32-hex flags (case-insensitive)" -ForegroundColor Yellow
$flagCount = 0
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flagCount += [regex]::Matches($c, "\b[a-fA-F0-9]{32}\b").Count
}
if ($flagCount -eq 0) { Write-Pass "0 real flags" } else { Write-Fail "$flagCount real flags" }

# 11. LEAKS FROM DICT
Write-Host "`n[11] Leaks from masking-dict.ps1" -ForegroundColor Yellow
if (Test-Path "masking-dict.ps1") {
    Remove-Variable replacements -ErrorAction SilentlyContinue
    . .\masking-dict.ps1 | Out-Null
    Write-Pass "masking-dict.ps1 loaded: $($replacements.Count) entries"
    $leaks = @()
    foreach ($key in $replacements.Keys) {
        if ($key -match '^<.*>$') { continue }
        if ($key -match '^[a-fA-F0-9]{32}$') { continue }
        $count = 0
        Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
            $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
            $count += ([regex]::Matches($c, [regex]::Escape($key))).Count
        }
        if ($count -gt 0) { $leaks += "LEAK: '$key' x$count" }
    }
    if ($leaks.Count -eq 0) { Write-Pass "0 leaks" } else { Write-Fail "$($leaks.Count) leaks:"; $leaks | ForEach-Object { Write-Info "    $_" } }
} else { Write-Fail "masking-dict.ps1 missing" }

# 12. LONG DASHES / BROKEN CHARS
Write-Host "`n[12] Long dashes / broken chars" -ForegroundColor Yellow
$d = 0; $b = 0
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $d += [regex]::Matches($c, "[\u2013\u2014\u2212]").Count
    $b += [regex]::Matches($c, "[\uFFFD]").Count
}
if ($d -eq 0) { Write-Pass "0 long dashes" } else { Write-Fail "$d long dashes" }
if ($b -eq 0) { Write-Pass "0 broken chars" } else { Write-Fail "$b broken chars" }

# 13. MASKING ARTIFACTS
Write-Host "`n[14] Masking artifacts" -ForegroundColor Yellow
$artifacts = @('<PASSWORD>blog', '<PASSWORD>.htb', '<USER_FLAG>FLAG', '<ROOT_FLAG>FLAG', '<PASSWORD><PASSWORD>')
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($art))).Count
    }
    if ($count -gt 0) { Write-Fail "artifact '$art' x$count"; $a += $count }
}
if ($a -eq 0) { Write-Pass "0 artifacts" }

# 14. PLACEHOLDERS USAGE
Write-Host "`n[15] Placeholders usage" -ForegroundColor Yellow
$placeholders = @('<USER_FLAG>', '<ROOT_FLAG>', '<PASSWORD>', '<BCRYPT_HASH>', '<MYSQL_HASH>', '<SHA256_HASH>', '<TOKEN>', '<SESSION_ID>')
foreach ($ph in $placeholders) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($ph))).Count
    }
    if ($count -gt 0) { Write-Pass "$ph used x$count" } else { Write-Warn "$ph not used" }
}

# 15. DOCUMENTATION
Write-Host "`n[16] Documentation" -ForegroundColor Yellow
if (Test-Path "CHEATSHEET.md") {
    $cs = [System.IO.File]::ReadAllText((Join-Path (Get-Location) "CHEATSHEET.md"), $utf8)
    $sections = [regex]::Matches($cs, '(?m)^##\s+\d+\.\s').Count
    if ($sections -ge 10) { Write-Pass "CHEATSHEET.md has $sections sections" } else { Write-Warn "CHEATSHEET.md has only $sections sections" }
} else { Write-Fail "CHEATSHEET.md missing" }
if (Test-Path "METHODOLOGY.md") {
    $mt = [System.IO.File]::ReadAllText((Join-Path (Get-Location) "METHODOLOGY.md"), $utf8)
    $phases = [regex]::Matches($mt, '(?m)^##\s+Phase').Count
    if ($phases -ge 5) { Write-Pass "METHODOLOGY.md has $phases phases" } else { Write-Warn "METHODOLOGY.md has only $phases phases" }
} else { Write-Fail "METHODOLOGY.md missing" }

# 16. SCRIPTS
Write-Host "`n[17] Scripts" -ForegroundColor Yellow
if (Test-Path "mask.ps1") { Write-Pass "mask.ps1 exists" } else { Write-Fail "mask.ps1 missing" }
if (Test-Path "check.ps1") { Write-Pass "check.ps1 exists" } else { Write-Fail "check.ps1 missing" }
if (Test-Path "masking-dict.ps1") { Write-Pass "masking-dict.ps1 exists" } else { Write-Fail "masking-dict.ps1 missing" }
if (Test-Path "_WORKFLOW.md") { Write-Pass "_WORKFLOW.md exists" } else { Write-Warn "_WORKFLOW.md missing" }
if (Test-Path "update-readmes.ps1") { Write-Pass "update-readmes.ps1 exists" } else { Write-Warn "update-readmes.ps1 missing" }
if (Test-Path "mask.ps1") {
    $m = Get-Content "mask.ps1" -Raw
    if ($m -match 'masking-dict\.ps1') { Write-Pass "mask.ps1 references masking-dict.ps1" } else { Write-Fail "mask.ps1 does not reference dict" }
    if ($m -match 'etik səbəblərə görə maskalanmışdır') { Write-Pass "mask.ps1 recognizes Az Note" } else { Write-Warn "mask.ps1 does not recognize Az Note" }
}
if (Test-Path "check.ps1") {
    $chk = Get-Content "check.ps1" -Raw
    if ($chk -match '\[a-fA-F0-9\]') { Write-Pass "check.ps1 uses [a-fA-F0-9]" } else { Write-Fail "check.ps1 does not use [a-fA-F0-9]" }
    if ($chk -match '_WORKFLOW\.md') { Write-Pass "check.ps1 excludes _WORKFLOW.md" } else { Write-Warn "check.ps1 does not exclude _WORKFLOW.md" }
}

# 17. PRE-COMMIT HOOK
Write-Host "`n[18] Pre-commit hook" -ForegroundColor Yellow
if (Test-Path ".git\hooks\pre-commit") {
    $hook = Get-Content ".git\hooks\pre-commit" -Raw
    if ($hook -match 'check\.ps1') { Write-Pass "hook runs check.ps1" } else { Write-Fail "hook does not run check.ps1" }
    if ($hook -match 'exit 1') { Write-Pass "hook can block commit" } else { Write-Warn "hook does not block commit" }
} else { Write-Fail "pre-commit hook missing" }

# 18. ENCODING (UTF-8 BOM)
Write-Host "`n[19] Encoding (UTF-8 BOM)" -ForegroundColor Yellow
$bomIssues = @()
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -ne '_WORKFLOW.md' } | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { $bomIssues += $_.Name }
}
if ($bomIssues.Count -eq 0) { Write-Pass "all .md files have UTF-8 BOM" } else { Write-Warn "$($bomIssues.Count) .md files missing BOM:"; $bomIssues | Select-Object -First 5 | ForEach-Object { Write-Info "    $_" } }

# 20. LOCAL vs ORIGIN FILE LIST
Write-Host "`n[20] Local vs origin/main file list" -ForegroundColor Yellow
$localFiles = git ls-files | Sort-Object
$remoteFiles = git ls-tree -r --name-only origin/main 2>$null | Sort-Object
$diff = Compare-Object $localFiles $remoteFiles
if (-not $diff) { Write-Pass "local and origin/main track the same files" } else { Write-Fail "file list differs"; $diff | Select-Object -First 10 | ForEach-Object { Write-Info "    $($_.SideIndicator) $($_.InputObject)" } }

# 20. LANGUAGE PAIRS PER CATEGORY
Write-Host "`n[21] Language pairs per category" -ForegroundColor Yellow
$categories = Get-ChildItem -Path "01 HTB" -Directory -Recurse | Where-Object {
    (Test-Path (Join-Path $_.FullName "01 Az")) -and
    (Test-Path (Join-Path $_.FullName "02 En")) -and
    (Test-Path (Join-Path $_.FullName "03 Ru"))
}
Write-Info "categories with 01 Az/02 En/03 Ru: $($categories.Count)"
foreach ($cat in $categories) {
    $az = @(Get-ChildItem (Join-Path $cat.FullName "01 Az") -Filter *.md -EA SilentlyContinue).Count
    $en = @(Get-ChildItem (Join-Path $cat.FullName "02 En") -Filter *.md -EA SilentlyContinue).Count
    $ru = @(Get-ChildItem (Join-Path $cat.FullName "03 Ru") -Filter *.md -EA SilentlyContinue).Count
    $catName = $cat.FullName.Replace((Get-Location).Path + '\', '')
    if ($az -eq $en -and $en -eq $ru) {
        Write-Pass "$catName - Az=$az En=$en Ru=$ru"
    } else {
        Write-Fail "$catName - Az=$az En=$en Ru=$ru (MISMATCH)"
    }
}

# 21. SUMMARY BY MACHINE COUNT
Write-Host "`n[22] Summary" -ForegroundColor Yellow
$totalMachines = 0
if ($categories.Count -gt 0) {
    foreach ($cat in $categories) {
        $az = @(Get-ChildItem (Join-Path $cat.FullName "01 Az") -Filter *.md -EA SilentlyContinue).Count
        $totalMachines += $az
    }
}
Write-Info "Total machines: $totalMachines"
Write-Info "Total walkthrough files: $($totalMachines * 3)"
if ($totalMachines * 3 -eq $walkthroughs.Count) {
    Write-Pass "machines x 3 = walkthrough files ($totalMachines x 3 = $($walkthroughs.Count))"
} else {
    Write-Warn "mismatch: $totalMachines x 3 = $($totalMachines * 3) vs found $($walkthroughs.Count)"
}

# SUMMARY
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  WARN: $warn" -ForegroundColor Yellow
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -eq 0 -and $warn -eq 0) { Write-Host "`n  PERFECT - repo fully ready" -ForegroundColor Green } elseif ($fail -eq 0) { Write-Host "`n  PASS - repo ready (some warnings)" -ForegroundColor Green } else { Write-Host "`n  FAIL - repo has issues" -ForegroundColor Red }
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     FINAL AUDIT v3 COMPLETE" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""