#!/usr/bin/env powershell
# Script to generate 100 advanced SQL injection test cases
# IDs 156-255 (Hard difficulty - Advanced patterns)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Generate 100 Advanced SQL Injection Cases" -ForegroundColor Cyan
Write-Host "  IDs 156-255 (Hard Difficulty)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "C:\Users\lando\jpamb\jpamb-sqli"
$javaSourceDir = "$projectRoot\src\main\java\jpamb\sqli"
$testCasesFile = "$projectRoot\test_cases_advanced_100.json"

if (-not (Test-Path $javaSourceDir)) {
    Write-Host "Error: Java source directory not found" -ForegroundColor Red
    exit 1
}

$testCases = @()

# ============================================
# Advanced StringBuilder Operations (156-175) - 20 cases
# ============================================

Write-Host "Generating Advanced StringBuilder (156-175)..." -ForegroundColor Red

for ($i = 156; $i -le 175; $i++) {
    $operations = @("append", "insert", "delete", "replace", "reverse")
    $op = $operations[$i % 5]
    
    $vulnCode = switch ($op) {
        "append" { @"
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE ");
    sb.append(input);
    String query = sb.toString();
"@ }
        "insert" { @"
    StringBuilder sb = new StringBuilder("SELECT * FROM users");
    sb.insert(sb.length(), " WHERE id = ");
    sb.insert(sb.length(), input);
    String query = sb.toString();
"@ }
        "delete" { @"
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = " + input);
    sb.delete(0, 0);
    String query = sb.toString();
"@ }
        "replace" { @"
    StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE placeholder");
    sb.replace(sb.indexOf("placeholder"), sb.length(), input);
    String query = sb.toString();
"@ }
        "reverse" { @"
    StringBuilder sb = new StringBuilder(input);
    sb.reverse();
    sb.reverse();
    String query = "SELECT * FROM users WHERE id = " + sb.toString();
"@ }
    }
    
    $safeCode = $vulnCode -replace "input", '"literal"'
    
    $testCases += @{
        id = $i
        name = "SQLi_AdvStringBuilder_${op}_$i"
        category = "advanced_stringbuilder"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_AdvStringBuilder_${op}_$i {
    public static void vulnerable(String input) {
$vulnCode
        executeQuery(query);
    }
    
    public static void safe() {
$safeCode
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# ============================================
# Method Call Chains (176-195) - 20 cases
# ============================================

Write-Host "Generating Method Call Chains (176-195)..." -ForegroundColor Red

for ($i = 176; $i -le 195; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_MethodChain_$i"
        category = "method_chaining"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_MethodChain_$i {
    public static void vulnerable(String input) {
        String processed = transformInput(input);
        String query = buildQuery(processed);
        executeQuery(query);
    }
    
    public static void safe() {
        String processed = transformInput("literal");
        String query = buildQuery(processed);
        executeQuery(query);
    }
    
    private static String transformInput(String s) {
        return s.trim().toLowerCase();
    }
    
    private static String buildQuery(String value) {
        return "SELECT * FROM users WHERE name = '" + value + "'";
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# ============================================
# Nested Loops with Accumulation (196-210) - 15 cases
# ============================================

Write-Host "Generating Nested Loops (196-210)..." -ForegroundColor Red

for ($i = 196; $i -le 210; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_NestedLoop_$i"
        category = "nested_loops"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_NestedLoop_$i {
    public static void vulnerable(String[][] inputs) {
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < inputs.length; i++) {
            for (int j = 0; j < inputs[i].length; j++) {
                query += inputs[i][j] + " OR ";
            }
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[][] literals = {{"a", "b"}, {"c", "d"}};
        String query = "SELECT * FROM users WHERE ";
        for (int i = 0; i < literals.length; i++) {
            for (int j = 0; j < literals[i].length; j++) {
                query += literals[i][j] + " OR ";
            }
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

# ============================================
# Array Manipulation (211-225) - 15 cases
# ============================================

Write-Host "Generating Array Manipulation (211-225)..." -ForegroundColor Red

for ($i = 211; $i -le 225; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_ArrayManip_$i"
        category = "array_operations"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_ArrayManip_$i {
    public static void vulnerable(String[] inputs) {
        String[] processed = new String[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            processed[i] = inputs[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"1", "2", "3"};
        String[] processed = new String[literals.length];
        for (int i = 0; i < literals.length; i++) {
            processed[i] = literals[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# ============================================
# Conditional Assignment (226-235) - 10 cases
# ============================================

Write-Host "Generating Conditional Assignment (226-235)..." -ForegroundColor Red

for ($i = 226; $i -le 235; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_CondAssign_$i"
        category = "conditional_assignment"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_CondAssign_$i {
    public static void vulnerable(String input, boolean useInput) {
        String value = useInput ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    public static void safe(boolean useInput) {
        String value = useInput ? "literal" : "default";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}
"@
    }
}

# ============================================
# Switch with Multiple Cases (236-245) - 10 cases
# ============================================

Write-Host "Generating Switch Cases (236-245)..." -ForegroundColor Red

for ($i = 236; $i -le 245; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_SwitchMulti_$i"
        category = "switch_statements"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_SwitchMulti_$i {
    public static void vulnerable(String input, int mode) {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = '" + input + "'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = " + input;
                break;
            default:
                query = "SELECT * FROM users WHERE email = '" + input + "'";
        }
        executeQuery(query);
    }
    
    public static void safe(int mode) {
        String query;
        switch (mode) {
            case 1:
                query = "SELECT * FROM users WHERE name = 'literal'";
                break;
            case 2:
                query = "SELECT * FROM users WHERE id = 42";
                break;
            default:
                query = "SELECT * FROM users WHERE email = 'test@example.com'";
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

# ============================================
# While Loop Accumulation (246-255) - 10 cases
# ============================================

Write-Host "Generating While Loops (246-255)..." -ForegroundColor Red

for ($i = 246; $i -le 255; $i++) {
    $testCases += @{
        id = $i
        name = "SQLi_WhileLoop_$i"
        category = "while_loops"
        difficulty = "hard"
        code = @"
package jpamb.sqli;

public class SQLi_WhileLoop_$i {
    public static void vulnerable(String[] inputs) {
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < inputs.length) {
            query += inputs[idx] + " OR ";
            idx++;
        }
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"admin", "user", "guest"};
        String query = "SELECT * FROM users WHERE ";
        int idx = 0;
        while (idx < literals.length) {
            query += literals[idx] + " OR ";
            idx++;
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

# ============================================
# Generate Java Files
# ============================================

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
Write-Host "Creating test_cases_advanced_100.json..." -ForegroundColor Cyan

$jsonData = @{
    version = "2.0"
    total_cases = 100
    id_range = "156-255"
    description = "100 advanced SQL injection test cases (hard difficulty)"
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
        description = "Advanced $($test.category) pattern"
    }
}

$jsonString = $jsonData | ConvertTo-Json -Depth 10
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($testCasesFile, $jsonString, $utf8NoBom)

Write-Host "Created test_cases_advanced_100.json" -ForegroundColor Green

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Generation Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Generated: 100 advanced test cases (IDs 156-255)" -ForegroundColor White
Write-Host ""
Write-Host "Categories:" -ForegroundColor White
Write-Host "  Advanced StringBuilder: 20 cases" -ForegroundColor Gray
Write-Host "  Method Chaining: 20 cases" -ForegroundColor Gray
Write-Host "  Nested Loops: 15 cases" -ForegroundColor Gray
Write-Host "  Array Operations: 15 cases" -ForegroundColor Gray
Write-Host "  Conditional Assignment: 10 cases" -ForegroundColor Gray
Write-Host "  Switch Statements: 10 cases" -ForegroundColor Gray
Write-Host "  While Loops: 10 cases" -ForegroundColor Gray
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Compile: javac -d bin src/main/java/jpamb/sqli/SQLi_*.java" -ForegroundColor Cyan
Write-Host "  2. Merge with existing test_cases.json" -ForegroundColor Cyan
Write-Host "  3. Run: python test_runner.py --jpamb-path . --analyzer my_analyzer.py" -ForegroundColor Cyan
Write-Host ""
