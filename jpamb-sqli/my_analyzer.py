#!/usr/bin/env python3
"""
Improved SQL Injection Analyzer for JPAMB Test Suite
Version 4: Added inter-procedural analysis, array tracking, and ternary operators
Target: 80%+ pass rate (204+/255)
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

def extract_all_methods(source_code):
    """
    Extract all method bodies from the source file for inter-procedural analysis
    Returns: dict of {method_name: (body, params)}
    """
    methods = {}
    
    # Pattern to match method declarations
    pattern = r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*\{'
    
    for match in re.finditer(pattern, source_code):
        method_name = match.group(1)
        params = match.group(2)
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
            body = source_code[start + 1:pos - 1].strip()
            methods[method_name] = (body, params)
    
    return methods

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
                name = parts[-1].replace('[]', '').replace('...', '')
                param_names.add(name)
    
    return param_names

def analyze_method_calls(method_body, all_methods, untrusted_sources, trusted_vars):
    """
    Analyze method calls to track taint propagation across methods
    AND check if called methods contain SQL injection patterns
    Returns: (set of untrusted variables, bool indicating SQL injection found)
    """
    new_untrusted = set()
    sql_injection_found = False
    
    # Find all method calls: var = methodName(args) OR just methodName(args)
    method_call_pattern = r'(?:(\w+)\s*=\s*)?(\w+)\s*\(([^)]*)\)'
    
    for match in re.finditer(method_call_pattern, method_body):
        result_var = match.group(1)  # May be None if no assignment
        called_method = match.group(2)
        args = match.group(3)
        
        # Check if the called method exists in our source
        if called_method in all_methods:
            called_body, called_params = all_methods[called_method]
            
            # Check if any argument is untrusted
            arg_list = [a.strip().strip('"') for a in args.split(',') if a.strip()]
            has_untrusted_arg = False
            
            for arg in arg_list:
                arg_name = arg.split('.')[-1]
                if arg_name in untrusted_sources or arg_name in new_untrusted:
                    has_untrusted_arg = True
                    break
            
            if has_untrusted_arg:
                # Mark result as untrusted if there is one
                if result_var:
                    new_untrusted.add(result_var)
                
                # CHECK: Does the called method contain SQL injection patterns?
                # Look for string concatenation in the called method
                if re.search(r'"[^"]*"\s*\+\s*\w+', called_body) or re.search(r'\w+\s*\+\s*"[^"]*"', called_body):
                    # The called method does string concatenation with its parameters
                    sql_injection_found = True
                
                # Check for StringBuilder append
                if 'StringBuilder' in called_body or 'StringBuffer' in called_body:
                    if re.search(r'\.append\s*\(\s*\w+\s*\)', called_body):
                        sql_injection_found = True
        else:
            # For unknown methods, check if arguments are untrusted
            arg_list = [a.strip() for a in args.split(',') if a.strip()]
            for arg in arg_list:
                if arg in untrusted_sources or arg in new_untrusted:
                    if result_var:
                        new_untrusted.add(result_var)
                    break
    
    return new_untrusted, sql_injection_found

def track_array_elements(method_body, untrusted_sources):
    """
    Track array element taint propagation
    If an array contains untrusted elements, accessing it produces untrusted data
    Returns: (new_untrusted, untrusted_arrays, sql_injection_found)
    """
    untrusted_arrays = set()
    new_untrusted = set()
    sql_injection_found = False
    
    # Pattern 1: Array initialization with untrusted values
    # String[] arr = {input1, input2}
    array_init_pattern = r'(\w+)\s*=\s*\{([^}]+)\}'
    for match in re.finditer(array_init_pattern, method_body):
        array_name = match.group(1)
        elements = match.group(2)
        
        # Check if any element is untrusted
        for elem in elements.split(','):
            elem = elem.strip().strip('"')
            if elem in untrusted_sources:
                untrusted_arrays.add(array_name)
                break
    
    # Pattern 2: Array assignment arr[i] = input
    array_assign_pattern = r'(\w+)\s*\[\s*\w+\s*\]\s*=\s*(\w+)'
    for match in re.finditer(array_assign_pattern, method_body):
        array_name = match.group(1)
        value = match.group(2)
        
        if value in untrusted_sources:
            untrusted_arrays.add(array_name)
    
    # Pattern 3: Array element access var = arr[i]
    array_access_pattern = r'(\w+)\s*=\s*(\w+)\s*\['
    for match in re.finditer(array_access_pattern, method_body):
        var_name = match.group(1)
        array_name = match.group(2)
        
        if array_name in untrusted_arrays or array_name in untrusted_sources:
            new_untrusted.add(var_name)
            
            # Check if this variable is used in SQL concatenation
            if re.search(rf'"[^"]*"\s*\+\s*{var_name}', method_body) or \
               re.search(rf'{var_name}\s*\+\s*"[^"]*"', method_body):
                sql_injection_found = True
    
    # Pattern 4: Enhanced for loop - for (String item : array)
    enhanced_for_pattern = r'for\s*\(\s*\w+\s+(\w+)\s*:\s*(\w+)'
    for match in re.finditer(enhanced_for_pattern, method_body):
        loop_var = match.group(1)
        array_name = match.group(2)
        
        if array_name in untrusted_arrays or array_name in untrusted_sources:
            new_untrusted.add(loop_var)
            
            # Check if loop variable is used in concatenation
            if re.search(rf'\+=\s*{loop_var}', method_body):
                sql_injection_found = True
    
    return new_untrusted, untrusted_arrays, sql_injection_found

def track_ternary_operators(method_body, untrusted_sources, trusted_vars):
    """
    Track taint propagation through ternary operators
    var = condition ? value1 : value2
    Returns: (new_untrusted, sql_injection_found)
    """
    new_untrusted = set()
    sql_injection_found = False
    trusted_ternary_results = set()
    
    # Pattern: var = condition ? val1 : val2
    ternary_pattern = r'(\w+)\s*=\s*[^?]+\?\s*([^:]+)\s*:\s*([^;]+)'
    
    for match in re.finditer(ternary_pattern, method_body):
        result_var = match.group(1)
        true_val = match.group(2).strip()
        false_val = match.group(3).strip()
        
        # Check if values are literals (strings in quotes)
        true_is_literal = true_val.startswith('"') and true_val.endswith('"')
        false_is_literal = false_val.startswith('"') and false_val.endswith('"')
        
        # If both are literals, mark result as trusted
        if true_is_literal and false_is_literal:
            trusted_ternary_results.add(result_var)
            continue
        
        # Extract variable names if not literals
        true_var = true_val if not true_is_literal else None
        false_var = false_val if not false_is_literal else None
        
        # Check if either branch uses untrusted data
        true_untrusted = False
        false_untrusted = False
        
        if true_var:
            true_untrusted = (true_var in untrusted_sources or 
                            (true_var not in trusted_vars and not true_var.isdigit()))
        
        if false_var:
            false_untrusted = (false_var in untrusted_sources or 
                             (false_var not in trusted_vars and not false_var.isdigit()))
        
        if true_untrusted or false_untrusted:
            new_untrusted.add(result_var)
            
            # Check if this result is used in SQL concatenation later
            if re.search(rf'"[^"]*"\s*\+\s*{result_var}', method_body) or \
               re.search(rf'{result_var}\s*\+\s*"[^"]*"', method_body):
                sql_injection_found = True
    
    # Add trusted ternary results to trusted vars
    trusted_vars.update(trusted_ternary_results)
    
    return new_untrusted, sql_injection_found

def track_loop_variables(method_body, untrusted_sources, trusted_vars):
    """
    Track variables that accumulate untrusted data in loops
    Returns: (new_untrusted, sql_injection_found)
    """
    new_untrusted = set()
    sql_injection_found = False
    
    # Pattern 1: query += input (inside loops)
    loop_patterns = [
        r'for\s*\([^)]+\)\s*\{([^}]+)\}',
        r'while\s*\([^)]+\)\s*\{([^}]+)\}',
        r'for\s*\([^)]+\)\s*\{((?:[^{}]|\{[^}]*\})*)\}',  # Handle nested braces
    ]
    
    for loop_pattern in loop_patterns:
        for match in re.finditer(loop_pattern, method_body, re.DOTALL):
            loop_body = match.group(1)
            
            # Look for += operations in loop
            plus_eq_pattern = r'(\w+)\s*\+=\s*[^;]+'
            for plus_match in re.finditer(plus_eq_pattern, loop_body):
                accumulator = plus_match.group(1)
                right_side = plus_match.group(0).split('+=', 1)[1].strip()
                
                # Check if any variable in the right side is untrusted
                vars_in_expression = re.findall(r'\b(\w+)\b', right_side)
                has_untrusted = False
                
                for var in vars_in_expression:
                    # Skip if it's a trusted variable or array access from trusted array
                    if var in trusted_vars:
                        continue
                    # Check for array access like processed[i]
                    if re.search(rf'{var}\s*\[', right_side):
                        # This is an array access, check if array is trusted
                        if var not in trusted_vars and (var in untrusted_sources or var in new_untrusted):
                            has_untrusted = True
                            break
                    elif var in untrusted_sources or var in new_untrusted:
                        has_untrusted = True
                        break
                
                if has_untrusted:
                    new_untrusted.add(accumulator)
                    sql_injection_found = True
            
            # Look for array access patterns
            if re.search(r'\w+\s*\[\s*[ijk]\s*\]', loop_body):
                array_use = re.findall(r'(\w+)\s*\[', loop_body)
                for arr in array_use:
                    # Only flag if array is untrusted
                    if arr in untrusted_sources or (arr in new_untrusted and arr not in trusted_vars):
                        concat_in_loop = re.findall(r'(\w+)\s*\+=.*' + arr, loop_body)
                        new_untrusted.update(concat_in_loop)
                        if concat_in_loop:
                            sql_injection_found = True
    
    return new_untrusted, sql_injection_found

def check_safe_patterns(method_body, method_name):
    """
    Check for patterns that indicate the method is safe
    Returns True if safe patterns detected
    """
    # Pattern 1: Strong regex sanitization
    if 'replaceAll' in method_body:
        if re.search(r'replaceAll\s*\(\s*"[^"]*\[\^[0-9a-zA-Z_\s-]+\][^"]*"\s*,\s*""', method_body):
            return True
    
    # Pattern 2: Parameterized queries / PreparedStatement
    if 'PreparedStatement' in method_body or 'setString' in method_body:
        return True
    
    # Pattern 3: Integer parsing (converts to safe type)
    if 'Integer.parseInt' in method_body or 'Long.parseLong' in method_body:
        return True
    
    # Pattern 4: Whitelist validation with equals
    if '.equals(' in method_body:
        equals_count = method_body.count('.equals(')
        if_count = method_body.count('if')
        if equals_count >= 1 and if_count >= 1:
            return True
    
    # Pattern 5: Enum or constant-based queries
    if 'switch' in method_body and 'case' in method_body:
        case_matches = re.findall(r'case\s+"[^"]*":', method_body)
        if len(case_matches) >= 2:
            return True
    
    # Pattern 6: Using reversed/transformed literal strings
    if 'new StringBuilder("' in method_body and '.reverse()' in method_body:
        return True
    
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
    
    safe_constants = {'true', 'false', 'null', 'this', 'length', 'size', 'empty'}
    if var_name.lower() in safe_constants:
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
    
    # Array initializations with literals - IMPORTANT for array tracking
    # Handle both 1D: {"a", "b"} and 2D: {{"a", "b"}, {"c", "d"}}
    array_matches = re.findall(r'(\w+)\s*=\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', method_body)
    for var, content in array_matches:
        # Remove inner braces for checking
        content_flat = re.sub(r'[{}]', '', content)
        # Check if all elements are string literals or numbers
        if re.match(r'^[\s"\'0-9a-zA-Z,._-]*$', content_flat):
            if var not in untrusted_sources:
                trusted_vars.add(var)
    
    # NEW: Track arrays created from trusted arrays
    # String[] processed = new String[literals.length]
    new_array_pattern = r'(\w+)\s*=\s*new\s+\w+\[(\w+)\.length\]'
    for match in re.finditer(new_array_pattern, method_body):
        new_array = match.group(1)
        source_array = match.group(2)
        if source_array in trusted_vars:
            # This new array will be filled from a trusted source
            # Check if it's only populated from the trusted source
            assign_pattern = rf'{new_array}\s*\[\s*\w+\s*\]\s*=\s*(\w+)\s*\['
            assignments = re.findall(assign_pattern, method_body)
            if all(src in trusted_vars or src == source_array for src in assignments):
                trusted_vars.add(new_array)
    
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
        
        # NEW: Array element assignments from trusted sources
        # processed[i] = literals[i].trim()
        array_elem_assign = re.findall(r'(\w+)\s*\[\s*\w+\s*\]\s*=\s*(\w+)\s*\[', method_body)
        for target_array, source_array in array_elem_assign:
            if source_array in trusted_vars:
                trusted_vars.add(target_array)
        
        if len(trusted_vars) == initial_size:
            break
    
    return trusted_vars

def analyze_for_sql_injection(method_body, method_name, params_string, all_methods):
    """
    Comprehensive analysis for SQL injection vulnerabilities with inter-procedural analysis
    """
    if not method_body:
        return "error", 0
    
    # Get parameter names - these are our untrusted sources
    untrusted_sources = extract_parameter_names(params_string)
    
    # FIRST: Check for safe patterns
    if check_safe_patterns(method_body, method_name):
        return "ok", 100
    
    # NEW: Track taint propagation through method calls AND check for SQL injection in called methods
    method_call_untrusted, method_call_sqli = analyze_method_calls(method_body, all_methods, untrusted_sources, set())
    untrusted_sources.update(method_call_untrusted)
    
    # If SQL injection found in called methods, report it
    if method_call_sqli:
        return "SQL injection", 95
    
    # NEW: Track array element taint
    array_untrusted, untrusted_arrays, array_sqli = track_array_elements(method_body, untrusted_sources)
    untrusted_sources.update(array_untrusted)
    
    if array_sqli:
        return "SQL injection", 95
    
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
    
    # Extract trusted variables EARLY - needed for all advanced tracking
    trusted_vars = extract_trusted_vars(method_body, untrusted_sources)
    
    # NEW: Track ternary operators - returns trusted ternary results
    ternary_untrusted, ternary_sqli = track_ternary_operators(method_body, untrusted_sources, trusted_vars)
    untrusted_sources.update(ternary_untrusted)
    # Note: trusted_vars is updated inside track_ternary_operators
    
    if ternary_sqli:
        return "SQL injection", 95
    
    # NEW: Track loop variable accumulation
    loop_untrusted, loop_sqli = track_loop_variables(method_body, untrusted_sources, trusted_vars)
    untrusted_sources.update(loop_untrusted)
    
    if loop_sqli:
        return "SQL injection", 95
    
    # Special case: if all StringBuilder operations are on trusted vars
    if 'StringBuilder' in method_body or 'StringBuffer' in method_body:
        untrusted_used = False
        
        append_matches = re.finditer(r'\.append\s*\(\s*(\w+)\s*\)', method_body)
        for match in append_matches:
            var_name = match.group(1)
            if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                untrusted_used = True
                break
        
        if not untrusted_used:
            append_method_matches = re.finditer(r'\.append\s*\(\s*(\w+)\.\w+\s*\(', method_body)
            for match in append_method_matches:
                var_name = match.group(1)
                if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                    untrusted_used = True
                    break
        
        if not untrusted_used:
            insert_matches = re.finditer(r'\.insert\s*\([^,]+,\s*(\w+)\s*\)', method_body)
            for match in insert_matches:
                var_name = match.group(1)
                if is_var_untrusted(var_name, untrusted_sources, trusted_vars):
                    untrusted_used = True
                    break
        
        if not untrusted_used:
            return "ok", 90
    
    # Check for various SQL injection patterns
    
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
    
    # Extract all methods for inter-procedural analysis
    all_methods = extract_all_methods(source_code)
    
    method_body, params = extract_method_body(source_code, method_name)
    
    if not method_body:
        print(f"Warning: Could not extract method body for {method_name}", file=sys.stderr)
        print("error;0", file=sys.stdout)
        sys.exit(1)
    
    print(f"Method body found ({len(method_body)} chars), params: {params}", file=sys.stderr)
    
    outcome, confidence = analyze_for_sql_injection(method_body, method_name, params, all_methods)
    
    print(f"{outcome};{confidence}", file=sys.stdout)
    
    print(f"Analysis complete: {outcome} (confidence: {confidence})", file=sys.stderr)

if __name__ == "__main__":
    main()