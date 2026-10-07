# mask.ps1
# Mask sensitive data in .md files.
# Requires masking-dict.ps1 in the same directory.
# Usage: .\mask.ps1

$ErrorActionPreference = "Stop"
$repo = "C:\Users\Irshad\Documents\GitHub\MethodMan"
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
      Where-Object { $_.FullName -notmatch '\\\.git\\' } |
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

$note = "> Note: All flags, passwords, and hashes have been masked for ethical reasons.`r`n"
Write-Host "`n=== Adding note after Attack Chain ===" -ForegroundColor Cyan
$filesWithNote = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Name -notin @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', '_WORKFLOW.md') } |
  ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8)
    if ($content -match "have been masked for ethical reasons" -or $content -match "etik səbəblərə görə maskalanmışdır") {
        Write-Host "[SKIP] Note exists: $($_.Name)"
        return
    }
    $pattern = '(?s)(```text.*?```)\r?\n'
    if ($content -match $pattern) {
        $new = $content -replace $pattern, "`$1`r`n`r`n$note"
        [System.IO.File]::WriteAllText($_.FullName, $new, $utf8WithBom)
        Write-Host "[NOTE] $($_.Name)"
        $filesWithNote++
    } else {
        Write-Host "[SKIP] No Attack Chain: $($_.Name)"
    }
  }
Write-Host "Notes added: $filesWithNote" -ForegroundColor Green