param(
    [switch]$IncludeDrafts
)

# mask.ps1
# Mask sensitive data in .md files.
# Requires masking-dict.ps1 in the same directory.
# Usage: .\mask.ps1

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

$dictPath = Join-Path $repo "masking-dict.ps1"
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found at $dictPath" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8WithBom = New-Object System.Text.UTF8Encoding($true)

Write-Host "`n=== Masking sensitive values ===" -ForegroundColor Cyan
$filesMasked = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and ($IncludeDrafts -or $_.FullName -notmatch '\\txt\\') -and $_.Name -notin @('_WORKFLOW.md', 'README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'SECURITY.md') } |
      ForEach-Object {
        $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8)
        $new = $content
        foreach ($key in $replacements.Keys) {
            $new = $new.Replace($key, $replacements[$key])
        }
        if ($content -ne $new) {
            [System.IO.File]::WriteAllText($_.FullName, $new, $utf8WithBom)
            Write-Host "[MASK] $($_.Name)"
            $filesMasked++
        }
      }
}
Write-Host "Files masked: $filesMasked" -ForegroundColor Green

function Get-NoteForFile($filePath) {
    if ($filePath -match '\\01 Az\\') {
        return "> [!NOTE]`r`n> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir."
    } elseif ($filePath -match '\\03 Ru\\') {
        return "> [!NOTE]`r`n> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям."
    } else {
        return "> [!NOTE]`r`n> All flags, passwords, hashes, and session tokens have been masked for ethical reasons."
    }
}
Write-Host "`n=== Adding note after Attack Chain ===" -ForegroundColor Cyan
$filesWithNote = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and ($IncludeDrafts -or $_.FullName -notmatch '\\txt\\') -and $_.Name -notin @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', '_WORKFLOW.md') } |
  ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8)
    $note = Get-NoteForFile $_.FullName
    $noteTexts = @(
        'All flags, passwords, hashes, and session tokens have been masked for ethical reasons',
        'Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям',
        'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir'
    )
    $hasNote = $false
    foreach ($nt in $noteTexts) { if ($content.Contains($nt)) { $hasNote = $true; break } }
    if ($hasNote) {
        Write-Host "[SKIP] Note exists: $($_.Name)" -ForegroundColor DarkGray
        return
    }
    $pattern = '(?s)(```text.*?```)\r?\n'
    if ($content -match $pattern) {
        $new = $content -replace $pattern, "`$1`r`n`r`n$note"
        [System.IO.File]::WriteAllText($_.FullName, $new, $utf8WithBom)
        Write-Host "[NOTE] $($_.Name)" -ForegroundColor Cyan
        $filesWithNote++
    } else {
        Write-Host "[SKIP] No Attack Chain: $($_.Name)" -ForegroundColor DarkGray
    }
  }
Write-Host "Notes added: $filesWithNote" -ForegroundColor Green