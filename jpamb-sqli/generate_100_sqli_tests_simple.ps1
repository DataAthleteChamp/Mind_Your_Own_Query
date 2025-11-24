#!/usr/bin/env powershell
# Simplified script to generate 100 SQL injection test cases
# IDs 31-130 (Medium difficulty, all guaranteed to compile)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Generate 100 SQL Injection Test Cases" -ForegroundColor Cyan
Write-Host "  IDs 31-130 (Medium Difficulty)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "C:\Users\lando\jpamb\jpamb-sqli"
$javaSourceDir = "$projectRoot\src\main\java\jpamb\sqli"
$testCasesFile = "$projectRoot\test_cases_100.json"

if (-not (Test-Path $javaSourceDir)) {
    Write-Host "Error: Java source directory not found" -ForegroundColor Red
    exit 1
}

$testCases = @()

# Simple Concatenation Variants (31-50) - 20 cases
Write-Host "Generating Simple Concatenation (31-50)..." -ForegroundColor Yellow

for ($i = 31; $i -le 50; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_Concat_$i"
        category = "concatenation"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_Concat_$i {
    public static void vulnerable(String input) {
        String query = "SELECT * FROM users WHERE id = " + input;
        executeQuery(query);
    }
    
    public static void safe() {
        String query = "SELECT * FROM users WHERE id = 42";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# Trim Operations (51-65) - 15 cases
Write-Host "Generating Trim Operations (51-65)..." -ForegroundColor Yellow

for ($i = 51; $i -le 65; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_Trim_$i"
        category = "string_ops"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_Trim_$i {
    public static void vulnerable(String input) {
        String processed = input.trim();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = "admin".trim();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# Case Conversion (66-80) - 15 cases
Write-Host "Generating Case Conversion (66-80)..." -ForegroundColor Yellow

for ($i = 66; $i -le 80; $i++) {
    $op = if ($i % 2 -eq 0) { "toUpperCase" } else { "toLowerCase" }
    
    $testCases += @{
        id = $i
        name = "SQLi_Case_$i"
        category = "string_ops"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_Case_$i {
    public static void vulnerable(String input) {
        String processed = input.$op();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = "admin".$op();
        String query = "SELECT * FROM users WHERE name = '" + processed + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# StringBuilder (81-95) - 15 cases
Write-Host "Generating StringBuilder (81-95)..." -ForegroundColor Yellow

for ($i = 81; $i -le 95; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_StringBuilder_$i"
        category = "string_builder"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_StringBuilder_$i {
    public static void vulnerable(String input) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append(input);
        sb.append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    public static void safe() {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append("admin");
        sb.append("'");
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# If-Else Branches (96-110) - 15 cases
Write-Host "Generating If-Else Branches (96-110)..." -ForegroundColor Yellow

for ($i = 96; $i -le 110; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_IfElse_$i"
        category = "control_flow"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_IfElse_$i {
    public static void vulnerable(String input, boolean flag) {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = '" + input + "'";
        } else {
            query = "SELECT * FROM users WHERE status = '" + input + "'";
        }
        executeQuery(query);
    }
    
    public static void safe(boolean flag) {
        String query;
        if (flag) {
            query = "SELECT * FROM users WHERE role = 'admin'";
        } else {
            query = "SELECT * FROM users WHERE status = 'active'";
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# For Loops (111-125) - 15 cases
Write-Host "Generating For Loops (111-125)..." -ForegroundColor Yellow

for ($i = 111; $i -le 125; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_ForLoop_$i"
        category = "loops"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_ForLoop_$i {
    public static void vulnerable(String[] inputs) {
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < inputs.length; j++) {
            query += inputs[j] + " OR ";
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        for (int j = 0; j < literals.length; j++) {
            query += literals[j] + " OR ";
        }
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# Format Strings (126-130) - 5 cases
Write-Host "Generating Format Strings (126-130)..." -ForegroundColor Yellow

for ($i = 126; $i -le 130; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_Format_$i"
        category = "formatting"
        difficulty = "medium"
        code = @"
package jpamb.sqli;

public class SQLi_Format_$i {
    public static void vulnerable(String input) {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", input);
        executeQuery(query);
    }
    
    public static void safe() {
        String query = String.format("SELECT * FROM users WHERE name = '%s'", "admin");
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# Generate Java Files
Write-Host "`nGenerating Java files..." -ForegroundColor Cyan

$successCount = 0
$errorCount = 0

foreach ($test in $testCases) {
    $className = $test.name
    $filePath = "$javaSourceDir\$className.java"
    
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($filePath, $test.code, $utf8NoBom)
        $successCount++
        
        if ($successCount % 25 -eq 0) {
            Write-Host "  Generated $successCount files..." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error creating $className.java: $_" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host "`nGenerated $successCount Java files" -ForegroundColor Green

# Create JSON
Write-Host "Creating test_cases_100.json..." -ForegroundColor Cyan

$jsonData = @{
    version = "2.0"
    total_cases = 100
    id_range = "31-130"
    description = "100 reliable SQL injection test cases"
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
    }
}

$jsonString = $jsonData | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($testCasesFile, $jsonString, $utf8NoBom)

Write-Host "Created test_cases_100.json" -ForegroundColor Green

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Generation Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Generated: 100 test cases (IDs 31-130)" -ForegroundColor White
Write-Host "Categories:" -ForegroundColor White
Write-Host "  Concatenation: 20 cases" -ForegroundColor Gray
Write-Host "  Trim Operations: 15 cases" -ForegroundColor Gray
Write-Host "  Case Conversion: 15 cases" -ForegroundColor Gray
Write-Host "  StringBuilder: 15 cases" -ForegroundColor Gray
Write-Host "  If-Else: 15 cases" -ForegroundColor Gray
Write-Host "  For Loops: 15 cases" -ForegroundColor Gray
Write-Host "  Format Strings: 5 cases" -ForegroundColor Gray
Write-Host ""
Write-Host "Next: javac -d bin src/main/java/jpamb/sqli/SQLi_*.java" -ForegroundColor Cyan
Write-Host ""
