#!/usr/bin/env powershell
# Script to generate 200 SQL injection test cases
# IDs 31-230 (Medium-Hard difficulty)
# Writes files WITHOUT BOM to avoid Java compilation errors

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Generate 200 SQL Injection Test Cases" -ForegroundColor Cyan
Write-Host "  IDs 31-230 (Medium-Hard)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$projectRoot = "C:\Users\lando\jpamb\jpamb-sqli"
$javaSourceDir = "$projectRoot\src\main\java\jpamb\sqli"
$testCasesFile = "$projectRoot\test_cases_200.json"

# Verify directories exist
if (-not (Test-Path $javaSourceDir)) {
    Write-Host "Error: Java source directory not found: $javaSourceDir" -ForegroundColor Red
    exit 1
}

# Test case array
$testCases = @()

# ============================================
# String Manipulation Chains (31-60) - 30 cases
# ============================================

Write-Host "Generating String Manipulation Chains (31-60)..." -ForegroundColor Yellow

for ($i = 31; $i -le 60; $i++) {
    $operations = @("trim", "toLowerCase", "toUpperCase", "substring", "replace")
    $op1 = $operations[$i % 5]
    $op2 = $operations[($i + 1) % 5]
    
    $testCases += @{
        id = $i
        name = "SQLi_Chain_${op1}_${op2}_$i"
        category = "string_manipulation"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable(String input) {
    String processed = input.$op1().$op2();
    String query = "SELECT * FROM users WHERE name = '" + processed + "'";
    executeQuery(query);
}
"@
        safe = @"
public static void safe() {
    String literal = "admin";
    String processed = literal.$op1().$op2();
    String query = "SELECT * FROM users WHERE name = '" + processed + "'";
    executeQuery(query);
}
"@
    }
}

# ============================================
# StringBuilder Patterns (61-90) - 30 cases
# ============================================

Write-Host "Generating StringBuilder Patterns (61-90)..." -ForegroundColor Yellow

for ($i = 61; $i -le 90; $i++) {
    $appendCount = (($i % 3) + 2)
    $appends = ""
    $safeAppends = ""
    $params = ""
    
    for ($j = 1; $j -le $appendCount; $j++) {
        $appends += "    sb.append(input$j);`n"
        $safeAppends += "    sb.append(`"literal$j`");`n"
        if ($j -eq 1) {
            $params = "String input$j"
        } else {
            $params += ", String input$j"
        }
    }
    
    $testCases += @{
        id = $i
        name = "SQLi_StringBuilder_Multi_$i"
        category = "string_builder"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable($params) {
    StringBuilder sb = new StringBuilder("SELECT * FROM data WHERE ");
$appends    String query = sb.toString();
    executeQuery(query);
}
"@
        safe = @"
public static void safe() {
    StringBuilder sb = new StringBuilder("SELECT * FROM data WHERE ");
$safeAppends    String query = sb.toString();
    executeQuery(query);
}
"@
    }
}

# ============================================
# Conditional Flows (91-120) - 30 cases
# ============================================

Write-Host "Generating Conditional Flows (91-120)..." -ForegroundColor Yellow

for ($i = 91; $i -le 120; $i++) {
    $conditions = @(
        "input.length() > 5",
        "input.contains(`"admin`")",
        "input.startsWith(`"user`")",
        "input.endsWith(`"test`")",
        "input.equals(`"guest`")"
    )
    $condition = $conditions[$i % 5]
    
    $testCases += @{
        id = $i
        name = "SQLi_Conditional_String_$i"
        category = "control_flow"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable(String input) {
    String query;
    if ($condition) {
        query = "SELECT * FROM users WHERE role = '" + input.toUpperCase() + "'";
    } else {
        query = "SELECT * FROM users WHERE status = '" + input.toLowerCase() + "'";
    }
    executeQuery(query);
}
"@
        safe = @"
public static void safe() {
    String literal = "guest";
    String query;
    if ($condition) {
        query = "SELECT * FROM users WHERE role = '" + literal.toUpperCase() + "'";
    } else {
        query = "SELECT * FROM users WHERE status = '" + literal.toLowerCase() + "'";
    }
    executeQuery(query);
}
"@
    }
}

# ============================================
# Loop-based Accumulation (121-150) - 30 cases
# ============================================

Write-Host "Generating Loop-based Accumulation (121-150)..." -ForegroundColor Yellow

for ($i = 121; $i -le 150; $i++) {
    $loopTypes = @("for", "while", "enhanced-for")
    $loopType = $loopTypes[$i % 3]
    
    $vulnerableLoop = switch ($loopType) {
        "for" { @"
    for (int j = 0; j < inputs.length; j++) {
        query += inputs[j] + " OR ";
    }
"@ }
        "while" { @"
    int j = 0;
    while (j < inputs.length) {
        query += inputs[j] + " OR ";
        j++;
    }
"@ }
        "enhanced-for" { @"
    for (String inp : inputs) {
        query += inp + " OR ";
    }
"@ }
    }
    
    $safeLoop = switch ($loopType) {
        "for" { @"
    for (int j = 0; j < literals.length; j++) {
        query += literals[j] + " OR ";
    }
"@ }
        "while" { @"
    int j = 0;
    while (j < literals.length) {
        query += literals[j] + " OR ";
        j++;
    }
"@ }
        "enhanced-for" { @"
    for (String lit : literals) {
        query += lit + " OR ";
    }
"@ }
    }
    
    $testCases += @{
        id = $i
        name = "SQLi_Loop_${loopType}_$i"
        category = "loops"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable(String[] inputs) {
    String query = "SELECT * FROM users WHERE ";
$vulnerableLoop    executeQuery(query);
}
"@
        safe = @"
public static void safe() {
    String[] literals = {"admin", "user", "guest"};
    String query = "SELECT * FROM users WHERE ";
$safeLoop    executeQuery(query);
}
"@
    }
}

# ============================================
# Try-Catch-Finally (151-180) - 30 cases
# ============================================

Write-Host "Generating Try-Catch-Finally (151-180)..." -ForegroundColor Yellow

for ($i = 151; $i -le 180; $i++) {
    $exceptions = @("SQLException", "IOException", "NullPointerException")
    $exceptionType = $exceptions[$i % 3]
    
    $testCases += @{
        id = $i
        name = "SQLi_TryCatch_${exceptionType}_$i"
        category = "exception_handling"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable(String input) {
    String query;
    try {
        query = "SELECT * FROM users WHERE id = " + input;
        executeQuery(query);
    } catch ($exceptionType e) {
        query = "SELECT * FROM logs WHERE error = '" + input + "'";
        executeQuery(query);
    } finally {
        String fallback = "SELECT * FROM audit WHERE trace = '" + input + "'";
        executeQuery(fallback);
    }
}
"@
        safe = @"
public static void safe() {
    String literal = "42";
    String query;
    try {
        query = "SELECT * FROM users WHERE id = " + literal;
        executeQuery(query);
    } catch ($exceptionType e) {
        query = "SELECT * FROM logs WHERE error = '" + literal + "'";
        executeQuery(query);
    } finally {
        String fallback = "SELECT * FROM audit WHERE trace = '" + literal + "'";
        executeQuery(fallback);
    }
}
"@
    }
}

# ============================================
# Format String Operations (181-200) - 20 cases
# ============================================

Write-Host "Generating Format String Operations (181-200)..." -ForegroundColor Yellow

for ($i = 181; $i -le 200; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_Format_$i"
        category = "string_formatting"
        difficulty = "medium"
        vulnerable = @"
public static void vulnerable(String input1, String input2) {
    String query = String.format("SELECT * FROM users WHERE name = '%s' AND role = '%s'", input1, input2);
    executeQuery(query);
}
"@
        safe = @"
public static void safe() {
    String query = String.format("SELECT * FROM users WHERE name = '%s' AND role = '%s'", "admin", "user");
    executeQuery(query);
}
"@
    }
}

# ============================================
# Complex Nested Control Flow (201-230) - 30 cases - HARD
# ============================================

Write-Host "Generating Complex Nested Control Flow (201-230)..." -ForegroundColor Red

for ($i = 201; $i -le 230; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_NestedComplex_$i"
        category = "nested_control"
        difficulty = "hard"
        vulnerable = @"
public static void vulnerable(String input1, String input2, boolean flag1, boolean flag2) {
    String query = "SELECT * FROM users WHERE ";
    if (flag1) {
        if (flag2) {
            query += "name = '" + input1.trim().toUpperCase() + "'";
        } else {
            String temp = input2.toLowerCase();
            for (int i = 0; i < temp.length(); i++) {
                query += temp.charAt(i);
            }
        }
    } else {
        query += "id = " + (input1.isEmpty() ? input2 : input1);
    }
    executeQuery(query);
}
"@
        safe = @"
public static void safe(boolean flag1, boolean flag2) {
    String query = "SELECT * FROM users WHERE ";
    if (flag1) {
        if (flag2) {
            query += "name = '" + "admin".toUpperCase() + "'";
        } else {
            String temp = "user".toLowerCase();
            for (int i = 0; i < temp.length(); i++) {
                query += temp.charAt(i);
            }
        }
    } else {
        query += "id = " + ("".isEmpty() ? "42" : "100");
    }
    executeQuery(query);
}
"@
    }
}

# ============================================
# Generate Java Files
# ============================================

Write-Host "`nGenerating Java files..." -ForegroundColor Cyan

$successCount = 0
$errorCount = 0

foreach ($test in $testCases) {
    $className = $test.name
    $filePath = "$javaSourceDir\$className.java"
    
    $javaContent = @"
package jpamb.sqli;

/**
 * Test Case ID: $($test.id)
 * Category: $($test.category)
 * Difficulty: $($test.difficulty)
 * 
 * This test case evaluates SQL injection detection in $($test.category) scenarios.
 */
public class $className {
    
    /**
     * VULNERABLE - Should detect SQL injection
     * This method contains a SQL injection vulnerability through $($test.category).
     */
$($test.vulnerable)
    
    /**
     * SAFE - Should NOT flag as vulnerable
     * This method uses only literal values.
     */
$($test.safe)
    
    /**
     * Helper method to simulate query execution
     */
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    
    try {
        # Write without BOM using .NET API
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($filePath, $javaContent, $utf8NoBom)
        $successCount++
        
        if ($successCount % 50 -eq 0) {
            Write-Host "  Generated $successCount files..." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error creating $className.java: $_" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host "`n✓ Generated $successCount Java files" -ForegroundColor Green
if ($errorCount -gt 0) {
    Write-Host "✗ Failed to create $errorCount files" -ForegroundColor Red
}

# ============================================
# Create JSON metadata
# ============================================

Write-Host "`nCreating test_cases_200.json..." -ForegroundColor Cyan

$jsonData = @{
    version = "2.0"
    total_cases = 200
    id_range = "31-230"
    description = "SQL Injection test suite - 200 new test cases (Medium-Hard difficulty)"
    test_cases = @()
}

foreach ($test in $testCases) {
    $jsonData.test_cases += @{
        id = $test.id
        name = $test.name
        vulnerable_method = "jpamb.sqli.$($test.name).vulnerable"
        safe_method = "jpamb.sqli.$($test.name).safe"
        category = $test.category
        difficulty = $test.difficulty
        description = "Tests $($test.category) patterns"
    }
}

# Convert to JSON and write without BOM
$jsonString = $jsonData | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($testCasesFile, $jsonString, $utf8NoBom)

Write-Host "✓ Created test_cases_200.json" -ForegroundColor Green

# ============================================
# Summary
# ============================================

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Generation Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  • Generated: 200 test cases (IDs 31-230)" -ForegroundColor White
Write-Host "  • Medium difficulty: 170 cases" -ForegroundColor Yellow
Write-Host "  • Hard difficulty: 30 cases" -ForegroundColor Red
Write-Host ""
Write-Host "Categories:" -ForegroundColor White
Write-Host "  • String Manipulation: 30 cases" -ForegroundColor Gray
Write-Host "  • StringBuilder: 30 cases" -ForegroundColor Gray
Write-Host "  • Control Flow: 30 cases" -ForegroundColor Gray
Write-Host "  • Loops: 30 cases" -ForegroundColor Gray
Write-Host "  • Exception Handling: 30 cases" -ForegroundColor Gray
Write-Host "  • String Formatting: 20 cases" -ForegroundColor Gray
Write-Host "  • Nested Control: 30 cases" -ForegroundColor Gray
Write-Host ""
Write-Host "Total Test Cases: 230 (30 existing + 200 new)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Compile: javac -d bin src/main/java/jpamb/sqli/*.java" -ForegroundColor Cyan
Write-Host "  2. Run tests: python test_runner.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "All files written WITHOUT BOM encoding ✓" -ForegroundColor Green
Write-Host ""
