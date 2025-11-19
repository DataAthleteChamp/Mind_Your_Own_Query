#!/usr/bin/env python3
"""
Improved SQL Injection Analyzer for JPAMB Test Suite
Version 3: Better safe pattern recognition to reduce false positives
"""

import sys
import re
from pathlib import Path

def parse_method_signature(method_sig):
    """
    Parse method signature like: jpamb.sqli.SQLi_DirectConcat.vulnerable
    Returns: (class_path, method_name)
    """
    parts = method_sig.rsplit('.', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None

def get_source_file_path(class_path):
    """
    Convert class path to source file path
    jpamb.sqli.SQLi_DirectConcat -> src/main/java/jpamb/sqli/SQLi_DirectConcat.java
    """
    file_path = class_path.replace('.', '/') + '.java'
    return Path('src/main/java') / file_path

def extract_method_body(source_code, method_name):
    """
    Extract the body of a specific method from Java source code
    """
    patterns = [
        rf'public\s+static\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
        rf'public\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
        rf'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, source_code)
        if match:
            start = match.end() - 1
            brace_count = 1
            pos = start + 1
            
            while pos < len(source_code) and brace_count > 0:
                if source_code[pos] == '{':
                    brace_count += 1
                elif source_code[pos] == '}':
                    brace_count -= 1
                pos += 1
            
            if brace_count == 0:
                params = match.group(1) if match.lastindex >= 1 else ""
                return source_code[start + 1:pos - 1].strip(), params
    
    return None, None

def extract_parameter_names(params_string):
    """
    Extract parameter names from method signature
    """
    if not params_string:
        return set()
    
    param_names = set()
    for param in params_string.split(','):
        param = param.strip()
        if param:
            parts = param.split()
            if parts:
                name = parts[-1].replace('[]', '')
                param_names.add(name)
    
    return param_names

def check_safe_patterns(method_body, method_name):
    """
    Check for patterns that indicate the method is safe
    Returns True if safe patterns detected
    """
    # Pattern 1: Strong regex sanitization
    if 'replaceAll' in method_body:
        # Whitelist patterns - only allow specific characters
        if re.search(r'replaceAll\s*\(\s*"[^"]*\[\^[0-9a-zA-Z_\s-]+\][^"]*"\s*,\s*""', method_body):
            return True
    
    # Pattern 2: Parameterized queries / PreparedStatement
    if 'PreparedStatement' in method_body or 'setString' in method_body:
        return True
    
    # Pattern 3: Using only literals (no parameters used in query construction)
    # If method builds query but never uses parameters
    if method_name == "safe":
        # Check for literal-only query building
        if '+ "' in method_body or '"' in method_body:
            # Look for patterns where only literals are concatenated
            pass
    
    # Pattern 4: Whitelist validation with equals
    if '.equals(' in method_body:
        # Check if there's conditional logic based on equals
        if 'if' in method_body and ('return' in method_body or '?' in method_body):
            # Likely whitelist pattern
            equals_count = method_body.count('.equals(')
            if_count = method_body.count('if')
            if equals_count >= 1 and if_count >= 1:
                return True
    
    # Pattern 5: Integer parsing (converts to safe type)
    if 'Integer.parseInt' in method_body or 'Long.parseLong' in method_body:
        return True
    
    # Pattern 6: Enum or constant-based queries
    if 'switch' in method_body and 'case' in method_body:
        # Check if the cases use literals
        case_matches = re.findall(r'case\s+"[^"]*":', method_body)
        if len(case_matches) >= 2:
            return True
    
    # Pattern 7: Using reversed/transformed literal strings
    # If StringBuilder operations result in a literal
    if 'new StringBuilder("' in method_body and '.reverse()' in method_body:
        # Reversing a literal is still safe
        return True
    
    # Pattern 8: Empty string initialization followed by literal assignment
    if '= ""' in method_body or '= new String()' in method_body:
        # Check if only literals are added
        pass
    
    return False

def is_var_untrusted(var_name, untrusted_sources, trusted_vars):
    """
    Determine if a variable is untrusted
    """
    if var_name in untrusted_sources:
        return True
    
    if var_name in trusted_vars:
        return False
    
    if var_name.isdigit():
        return False
    
    safe_constants = {'true', 'false', 'null', 'this', 'length', 'size'}
    if var_name.lower() in safe_constants:
        return False
    
    # Common loop variables are usually safe indices
    if var_name in {'i', 'j', 'k', 'index', 'idx'}:
        return False
    
    return True

def extract_trusted_vars(method_body, untrusted_sources):
    """
    Extract all variables that contain only literal/safe values
    """
    trusted_vars = set()
    
    # Find variable assignments to string literals
    literal_assignments = re.findall(r'(\w+)\s*=\s*"[^"]*"\s*;', method_body)
    for var in literal_assignments:
        if var not in untrusted_sources:
            trusted_vars.add(var)
    
    # Find assignments to new String("literal")
    new_string_literals = re.findall(r'(\w+)\s*=\s*new\s+String\s*\(\s*"[^"]*"\s*\)', method_body)
    for var in new_string_literals:
        if var not in untrusted_sources:
            trusted_vars.add(var)
    
    # Array initializations with literals
    array_matches = re.findall(r'(\w+)\s*=\s*\{([^}]*)\}', method_body)
    for var, content in array_matches:
        if re.match(r'^[\s"\'0-9a-zA-Z,._-]*$', content):
            if var not in untrusted_sources:
                trusted_vars.add(var)
    
    # Track derived literals
    safe_operations = ['substring', 'trim', 'toUpperCase', 'toLowerCase', 
                      'replace', 'replaceAll', 'replaceFirst', 'strip',
                      'stripLeading', 'stripTrailing', 'split', 'repeat',
                      'indent', 'formatted', 'reverse', 'toString']
    
    for _ in range(5):
        initial_size = len(trusted_vars)
        
        for op in safe_operations:
            pattern = rf'(\w+)\s*=\s*(\w+)\.{op}\s*\('
            matches = re.findall(pattern, method_body)
            for new_var, source_var in matches:
                if source_var in trusted_vars and new_var not in untrusted_sources:
                    trusted_vars.add(new_var)
            
            pattern2 = rf'(\w+)\s*=\s*"[^"]*"\.{op}\s*\('
            matches2 = re.findall(pattern2, method_body)
            for new_var in matches2:
                if new_var not in untrusted_sources:
                    trusted_vars.add(new_var)
        
        # StringBuilder with only literal appends
        if 'new StringBuilder("' in method_body:
            sb_matches = re.findall(r'(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*"[^"]*"\s*\)', method_body)
            for var in sb_matches:
                if var not in untrusted_sources:
                    trusted_vars.add(var)
        
        # Array access from trusted arrays
        array_access = re.findall(r'(\w+)\s*=\s*(\w+)\s*\[', method_body)
        for new_var, array_var in array_access:
            if array_var in trusted_vars and new_var not in untrusted_sources:
                trusted_vars.add(new_var)
        
        if len(trusted_vars) == initial_size:
            break
    
    return trusted_vars

def analyze_for_sql_injection(method_body, method_name, params_string):
    """
    Comprehensive analysis for SQL injection vulnerabilities
    """
    if not method_body:
        return "error", 0
    
    # Get parameter names - these are our untrusted sources
    untrusted_sources = extract_parameter_names(params_string)
    
    # FIRST: Check for safe patterns (especially for "safe" methods)
    if check_safe_patterns(method_body, method_name):
        return "ok", 100
    
    # Track variables derived from untrusted sources
    for _ in range(5):
        initial_size = len(untrusted_sources)
        
        for source in list(untrusted_sources):
            # Direct assignment
            pattern1 = rf'(\w+)\s*=\s*{source}\s*[;.]'
            matches1 = re.findall(pattern1, method_body)
            untrusted_sources.update(matches1)
            
            # Method call result on untrusted var
            pattern2 = rf'(\w+)\s*=\s*{source}\.\w+\s*\('
            matches2 = re.findall(pattern2, method_body)
            untrusted_sources.update(matches2)
            
            # Array access
            pattern3 = rf'(\w+)\s*=\s*{source}\s*\['
            matches3 = re.findall(pattern3, method_body)
            untrusted_sources.update(matches3)
        
        if len(untrusted_sources) == initial_size:
            break
    
    # Get trusted variables
    trusted_vars = extract_trusted_vars(method_body, untrusted_sources)
    
    # Special case: if all StringBuilder operations are on trusted vars
    if 'StringBuilder' in method_body or 'StringBuffer' in method_body:
        # Check if any untrusted var is actually used
        untrusted_used = False
        
        # Check append calls
        append_matches = re.finditer(r'\.append\s*\(\s*(\w+)\s*\)', method_body)
        for match in append_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                untrusted_used = True
                break
        
        if not untrusted_used:
            # Also check for append with method calls
            append_method_matches = re.finditer(r'\.append\s*\(\s*(\w+)\.\w+\s*\(', method_body)
            for match in append_method_matches:
                var_name = match.group(1)
                if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                    untrusted_used = True
                    break
        
        if not untrusted_used:
            # Check insert calls
            insert_matches = re.finditer(r'\.insert\s*\([^,]+,\s*(\w+)\s*\)', method_body)
            for match in insert_matches:
                var_name = match.group(1)
                if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                    untrusted_used = True
                    break
        
        if not untrusted_used:
            return "ok", 90
    
    # ================================================================
    # Check for various SQL injection patterns
    # ================================================================
    
    # 1. String concatenation with untrusted variables
    concat_patterns = [
        r'"[^"]*"\s*\+\s*(\w+)',
        r'(\w+)\s*\+\s*"[^"]*"',
    ]
    
    for pattern in concat_patterns:
        matches = re.finditer(pattern, method_body)
        for match in matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 100
    
    # 2. StringBuilder/StringBuffer append with untrusted variables
    if 'StringBuilder' in method_body or 'StringBuffer' in method_body:
        append_matches = re.finditer(r'\.append\s*\(\s*(\w+)\s*\)', method_body)
        for match in append_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
        
        append_method_matches = re.finditer(r'\.append\s*\(\s*(\w+)\.\w+\s*\(', method_body)
        for match in append_method_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
        
        insert_matches = re.finditer(r'\.insert\s*\([^,]+,\s*(\w+)\s*\)', method_body)
        for match in insert_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
    
    # 3. String.format with untrusted variables
    if 'String.format' in method_body or '.format(' in method_body or '.formatted(' in method_body:
        format_matches = re.finditer(r'(?:String\.format|\.format(?:ted)?)\s*\([^)]*,\s*(\w+)', method_body)
        for match in format_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
    
    # 4. Text blocks with concatenation
    if '"""' in method_body:
        if re.search(r'"""\s*\+\s*(\w+)', method_body):
            match = re.search(r'"""\s*\+\s*(\w+)', method_body)
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
    
    # 5. += operator with untrusted variables
    if '+=' in method_body:
        plus_eq_matches = re.finditer(r'\+=\s*(\w+)', method_body)
        for match in plus_eq_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
    
    # 6. StringJoiner with untrusted add
    if 'StringJoiner' in method_body:
        add_matches = re.finditer(r'\.add\s*\(\s*(\w+)\s*\)', method_body)
        for match in add_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 95
    
    # 7. Stream operations with untrusted data
    if 'stream' in method_body.lower() or 'Collectors' in method_body:
        stream_sources = re.findall(r'(\w+)\.stream\s*\(|Arrays\.stream\s*\(\s*(\w+)', method_body)
        for groups in stream_sources:
            for var_name in groups:
                if var_name and is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                    return "SQL injection", 90
    
    # 8. Character array operations
    if 'toCharArray' in method_body:
        char_sources = re.findall(r'(\w+)\.toCharArray\s*\(', method_body)
        for var_name in char_sources:
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 90
    
    # 9. Base64/encoding operations on untrusted data
    if 'Base64' in method_body:
        # Check if decoding untrusted input
        decode_pattern = r'decode\s*\(\s*(\w+)'
        decode_matches = re.findall(decode_pattern, method_body)
        for var_name in decode_matches:
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 90
    
    # 10. Map/collection iteration with untrusted values
    if 'Map' in method_body or 'HashMap' in method_body:
        entry_matches = re.findall(r'for\s*\([^:]+:\s*(\w+)\.', method_body)
        for var_name in entry_matches:
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                return "SQL injection", 90
    
    # If no dangerous patterns found, it's likely safe
    return "ok", 70

def main():
    if len(sys.argv) < 2:
        print("Usage: python my_analyzer.py <method_signature>", file=sys.stderr)
        print("Example: python my_analyzer.py jpamb.sqli.SQLi_DirectConcat.vulnerable", file=sys.stderr)
        sys.exit(1)
    
    method_sig = sys.argv[1]
    
    print(f"Analyzing: {method_sig}", file=sys.stderr)
    
    class_path, method_name = parse_method_signature(method_sig)
    
    if not class_path:
        print("error;0", file=sys.stdout)
        sys.exit(1)
    
    source_file = get_source_file_path(class_path)
    
    if not source_file.exists():
        print(f"Error: Source file not found: {source_file}", file=sys.stderr)
        print("error;0", file=sys.stdout)
        sys.exit(1)
    
    try:
        with open(source_file, 'r', encoding='utf-8') as f:
            source_code = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        print("error;0", file=sys.stdout)
        sys.exit(1)
    
    method_body, params = extract_method_body(source_code, method_name)
    
    if not method_body:
        print(f"Warning: Could not extract method body for {method_name}", file=sys.stderr)
        print("error;0", file=sys.stdout)
        sys.exit(1)
    
    print(f"Method body found ({len(method_body)} chars), params: {params}", file=sys.stderr)
    
    outcome, confidence = analyze_for_sql_injection(method_body, method_name, params)
    
    print(f"{outcome};{confidence}", file=sys.stdout)
    
    print(f"Analysis complete: {outcome} (confidence: {confidence})", file=sys.stderr)

if __name__ == "__main__":
    main()