#!/usr/bin/env powershell
# Script to merge original 30 test cases with new 100 test cases

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Merge Test Cases" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "C:\Users\lando\jpamb\jpamb-sqli"
$backupFile = "$projectRoot\test_cases.backup.json"
$new100File = "$projectRoot\test_cases_100.json"
$outputFile = "$projectRoot\test_cases.json"

# Read both JSON files
Write-Host "Reading original 30 test cases from backup..." -ForegroundColor Yellow
$original = Get-Content $backupFile -Raw | ConvertFrom-Json

Write-Host "Reading new 100 test cases..." -ForegroundColor Yellow
$new100 = Get-Content $new100File -Raw | ConvertFrom-Json

# Create merged data structure
$merged = @{
    version = "2.0"
    total_cases = 130
    description = "Complete SQL Injection test suite: 30 original + 100 new cases"
    test_cases = @()
}

# Add original 30 test cases
Write-Host "Adding original 30 test cases (IDs 1-30)..." -ForegroundColor Yellow
foreach ($test in $original.test_cases) {
    $merged.test_cases += $test
}

# Add new 100 test cases
Write-Host "Adding new 100 test cases (IDs 31-130)..." -ForegroundColor Yellow
foreach ($test in $new100.test_cases) {
    $merged.test_cases += $test
}

# Sort by ID to keep them in order
$merged.test_cases = $merged.test_cases | Sort-Object -Property id

# Write merged JSON
Write-Host "Writing merged test_cases.json..." -ForegroundColor Cyan
$jsonString = $merged | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputFile, $jsonString, $utf8NoBom)

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Merge Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  Original cases (1-30): 30" -ForegroundColor Green
Write-Host "  New cases (31-130): 100" -ForegroundColor Green
Write-Host "  Total cases: 130" -ForegroundColor Cyan
Write-Host ""
Write-Host "File created: test_cases.json" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Verify: python test_runner.py" -ForegroundColor Cyan
Write-Host ""
