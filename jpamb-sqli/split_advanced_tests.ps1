#!/usr/bin/env powershell
# Script to split advanced_sqli_tests.java into 30 separate files
# and set up the test suite
# FIXED: Uses UTF8 without BOM

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Split Advanced SQL Test Cases" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$sourceFile = "C:\Users\lando\OneDrive\Desktop\advanced_sqli_tests.java"
$targetDir = "C:\Users\lando\jpamb\jpamb-sqli\src\main\java\jpamb\sqli"
$baseDir = "C:\Users\lando\jpamb\jpamb-sqli"

# Create UTF8 encoding without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

# Check source file exists
if (-not (Test-Path $sourceFile)) {
    Write-Host "Error: Source file not found: $sourceFile" -ForegroundColor Red
    Write-Host "Please make sure advanced_sqli_tests.java is on your Desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host "Source: $sourceFile" -ForegroundColor Yellow
Write-Host "Target: $targetDir" -ForegroundColor Yellow
Write-Host ""

# Check target directory exists
if (-not (Test-Path $targetDir)) {
    Write-Host "Error: Target directory not found: $targetDir" -ForegroundColor Red
    exit 1
}

Write-Host "Step 1: Reading source file..." -ForegroundColor Yellow
$content = Get-Content $sourceFile -Raw
Write-Host "  Done - Read $($content.Length) characters" -ForegroundColor Green
Write-Host ""

Write-Host "Step 2: Splitting into individual Java files..." -ForegroundColor Yellow

# Define all 30 test classes
$testCases = @(
    @{num=26; name="StringBuilderConditional"},
    @{num=27; name="StringBuilderChaining"},
    @{num=28; name="StringBuilderHelper"},
    @{num=29; name="StringBuilderInsert"},
    @{num=30; name="StringBuilderDelete"},
    @{num=31; name="StringBuilderNestedLoop"},
    @{num=32; name="StringBuilderReverse"},
    @{num=33; name="StringBuilderCapacity"},
    @{num=34; name="StringBuilderReplace"},
    @{num=35; name="StringBuilderSetChar"},
    @{num=36; name="MultiLevelOps"},
    @{num=37; name="TernaryConcat"},
    @{num=38; name="FormatString"},
    @{num=39; name="StreamJoin"},
    @{num=40; name="RecursiveBuilder"},
    @{num=41; name="LambdaBuilder"},
    @{num=42; name="StringJoiner"},
    @{num=43; name="BatchQuery"},
    @{num=44; name="VariableChain"},
    @{num=45; name="MapBuilder"},
    @{num=46; name="EmptyString"},
    @{num=47; name="NullCoalesce"},
    @{num=48; name="Unicode"},
    @{num=49; name="Encoded"},
    @{num=50; name="RegexReplace"},
    @{num=51; name="Interpolation"},
    @{num=52; name="CharArray"},
    @{num=53; name="RepeatString"},
    @{num=54; name="TextBlock"},
    @{num=55; name="IndentString"}
)

$createdFiles = 0
$failedFiles = 0

foreach ($test in $testCases) {
    $className = "SQLi_$($test.name)"
    $fileName = "$className.java"
    $filePath = Join-Path $targetDir $fileName
    
    # Pattern to extract this specific class - simplified pattern
    $pattern = "(?s)public class $className \{.+?private static void executeQuery\(String q\) \{[^\}]+\}\s*\}"
    
    if ($content -match $pattern) {
        # Build the complete Java file
        $classCode = "package jpamb.sqli;`n`n" + $matches[0]
        
        # Write to file WITHOUT BOM
        [System.IO.File]::WriteAllText($filePath, $classCode, $utf8NoBom)
        Write-Host "  Created: $fileName" -ForegroundColor Green
        $createdFiles++
    } else {
        Write-Host "  Failed to extract: $className" -ForegroundColor Red
        $failedFiles++
    }
}

Write-Host ""
Write-Host "  Summary: $createdFiles files created, $failedFiles failed" -ForegroundColor Cyan
Write-Host ""

if ($failedFiles -gt 0) {
    Write-Host "Warning: Some files failed to extract. You may need to manually copy them." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Step 3: Updating test_cases.json..." -ForegroundColor Yellow

# Load existing test_cases.json
$testCasesFile = Join-Path $baseDir "test_cases.json"

if (Test-Path $testCasesFile) {
    $existingData = Get-Content $testCasesFile -Raw | ConvertFrom-Json
    $existingTests = @($existingData.test_cases)
    Write-Host "  Existing tests: $($existingTests.Count)" -ForegroundColor Cyan
} else {
    $existingTests = @()
    Write-Host "  No existing test_cases.json found" -ForegroundColor Yellow
}

# Add new test cases
$newTests = @()

# Categories for new tests
$categories = @{
    "StringBuilderConditional" = "advanced_stringbuilder"
    "StringBuilderChaining" = "advanced_stringbuilder"
    "StringBuilderHelper" = "advanced_stringbuilder"
    "StringBuilderInsert" = "advanced_stringbuilder"
    "StringBuilderDelete" = "advanced_stringbuilder"
    "StringBuilderNestedLoop" = "advanced_stringbuilder"
    "StringBuilderReverse" = "advanced_stringbuilder"
    "StringBuilderCapacity" = "advanced_stringbuilder"
    "StringBuilderReplace" = "advanced_stringbuilder"
    "StringBuilderSetChar" = "advanced_stringbuilder"
    "MultiLevelOps" = "complex_patterns"
    "TernaryConcat" = "complex_patterns"
    "FormatString" = "complex_patterns"
    "StreamJoin" = "complex_patterns"
    "RecursiveBuilder" = "complex_patterns"
    "LambdaBuilder" = "complex_patterns"
    "StringJoiner" = "complex_patterns"
    "BatchQuery" = "complex_patterns"
    "VariableChain" = "complex_patterns"
    "MapBuilder" = "complex_patterns"
    "EmptyString" = "edge_cases"
    "NullCoalesce" = "edge_cases"
    "Unicode" = "edge_cases"
    "Encoded" = "edge_cases"
    "RegexReplace" = "edge_cases"
    "Interpolation" = "edge_cases"
    "CharArray" = "edge_cases"
    "RepeatString" = "edge_cases"
    "TextBlock" = "edge_cases"
    "IndentString" = "edge_cases"
}

foreach ($test in $testCases) {
    $className = "SQLi_$($test.name)"
    $category = $categories[$test.name]
    
    $newTest = @{
        id = $test.num
        name = $className
        vulnerable_method = "jpamb.sqli.$className.vulnerable"
        safe_method = "jpamb.sqli.$className.safe"
        category = $category
        description = "Advanced test case $($test.num)"
        expected_vulnerable = $true
        expected_safe = $false
    }
    
    $newTests += $newTest
}

# Combine existing and new tests
$allTests = $existingTests + $newTests

# Create updated JSON
$updatedData = @{
    version = "2.0"
    total_cases = $allTests.Count
    test_cases = $allTests
}

# Backup existing file
if (Test-Path $testCasesFile) {
    $backupFile = Join-Path $baseDir "test_cases.backup.json"
    Copy-Item $testCasesFile $backupFile -Force
    Write-Host "  Backed up to test_cases.backup.json" -ForegroundColor Green
}

# Write updated file WITHOUT BOM
$jsonContent = $updatedData | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($testCasesFile, $jsonContent, $utf8NoBom)
Write-Host "  Updated test_cases.json" -ForegroundColor Green
Write-Host "  Total tests: $($allTests.Count)" -ForegroundColor Cyan
Write-Host ""

Write-Host "Step 4: Compiling Java files..." -ForegroundColor Yellow
Push-Location (Join-Path $baseDir "src\main\java")

$compileOutput = & javac jpamb/sqli/*.java 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Compilation successful" -ForegroundColor Green
} else {
    Write-Host "  Compilation had issues:" -ForegroundColor Yellow
    Write-Host $compileOutput -ForegroundColor Gray
}

Pop-Location
Write-Host ""

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files created: $createdFiles / 30" -ForegroundColor Cyan
Write-Host "Total tests: $($allTests.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Step - Run the tests:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  cd $baseDir" -ForegroundColor Gray
Write-Host "  python test_runner.py --jpamb-path . --analyzer my_analyzer.py" -ForegroundColor Gray
Write-Host ""

# Ask to run tests now
$runNow = Read-Host "Run tests now? (y/n)"
if ($runNow -eq 'y') {
    Push-Location $baseDir
    Write-Host ""
    Write-Host "Running test suite..." -ForegroundColor Cyan
    Write-Host ""
    python test_runner.py --jpamb-path . --analyzer my_analyzer.py
    Pop-Location
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green