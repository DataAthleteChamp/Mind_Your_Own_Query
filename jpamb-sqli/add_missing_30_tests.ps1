#!/usr/bin/env powershell
# Script to add the 30 missing advanced test cases to test_cases.json

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Add Missing 30 Advanced Test Cases" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "C:\Users\lando\jpamb\jpamb-sqli"
$testCasesFile = "$projectRoot\test_cases.json"

# List of missing test cases
$missingTests = @(
    "SQLi_BatchQuery",
    "SQLi_CharArray",
    "SQLi_EmptyString",
    "SQLi_Encoded",
    "SQLi_FormatString",
    "SQLi_IndentString",
    "SQLi_Interpolation",
    "SQLi_LambdaBuilder",
    "SQLi_MapBuilder",
    "SQLi_MultiLevelOps",
    "SQLi_NullCoalesce",
    "SQLi_RecursiveBuilder",
    "SQLi_RegexReplace",
    "SQLi_RepeatString",
    "SQLi_StreamJoin",
    "SQLi_StringBuilderCapacity",
    "SQLi_StringBuilderChaining",
    "SQLi_StringBuilderConditional",
    "SQLi_StringBuilderDelete",
    "SQLi_StringBuilderHelper",
    "SQLi_StringBuilderInsert",
    "SQLi_StringBuilderNestedLoop",
    "SQLi_StringBuilderReplace",
    "SQLi_StringBuilderReverse",
    "SQLi_StringBuilderSetChar",
    "SQLi_StringJoiner",
    "SQLi_TernaryConcat",
    "SQLi_TextBlock",
    "SQLi_Unicode",
    "SQLi_VariableChain"
)

# Read current test_cases.json
Write-Host "Reading current test_cases.json..." -ForegroundColor Yellow
$jsonData = Get-Content $testCasesFile | ConvertFrom-Json

# Find the highest current ID
$maxId = ($jsonData.test_cases | ForEach-Object { $_.id } | Measure-Object -Maximum).Maximum
Write-Host "Current highest ID: $maxId" -ForegroundColor Gray

# Add missing test cases with sequential IDs
Write-Host "Adding 30 missing advanced test cases..." -ForegroundColor Yellow
$newId = $maxId + 1

foreach ($testName in $missingTests) {
    $newTest = @{
        id = $newId
        name = $testName
        vulnerable_method = "jpamb.sqli.$testName.vulnerable"
        safe_method = "jpamb.sqli.$testName.safe"
        category = "advanced"
        difficulty = "hard"
        description = "Advanced SQL injection test case"
    }
    
    # Convert to PSCustomObject to match JSON structure
    $testObj = New-Object PSObject -Property $newTest
    $jsonData.test_cases += $testObj
    
    Write-Host "  Added: $testName (ID: $newId)" -ForegroundColor Gray
    $newId++
}

# Update total count
$jsonData.total_cases = $jsonData.test_cases.Count

# Sort test cases by ID
$jsonData.test_cases = $jsonData.test_cases | Sort-Object -Property id

# Backup current file
$backupFile = "$projectRoot\test_cases.backup_before_adding_30.json"
Copy-Item $testCasesFile $backupFile
Write-Host "`nBackup created: test_cases.backup_before_adding_30.json" -ForegroundColor Green

# Write updated JSON
Write-Host "Writing updated test_cases.json..." -ForegroundColor Cyan
$jsonString = $jsonData | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($testCasesFile, $jsonString, $utf8NoBom)

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Update Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  Previous total: 125 test cases" -ForegroundColor Gray
Write-Host "  Added: 30 advanced test cases" -ForegroundColor Green
Write-Host "  New total: 155 test cases" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test ID range: 1-155" -ForegroundColor White
Write-Host ""
Write-Host "Next: Run test suite with all 155 cases" -ForegroundColor Yellow
Write-Host "  python test_runner.py --jpamb-path C:\Users\lando\jpamb\jpamb-sqli --analyzer my_analyzer.py" -ForegroundColor Cyan
Write-Host ""
