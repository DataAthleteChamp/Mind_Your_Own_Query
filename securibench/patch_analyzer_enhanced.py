#!/usr/bin/env python3
"""Enhanced patch for my_analyzer.py to work with Securibench"""

import sys
from pathlib import Path

def patch_analyzer_enhanced(input_file, output_file):
    """Patch the analyzer to handle Securibench structure and servlet methods"""
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Patch 1: Fix get_source_file_path
    old_path_func = '''def get_source_file_path(class_path):
    """
    Convert class path to source file path
    jpamb.sqli.SQLi_DirectConcat -> src/main/java/jpamb/sqli/SQLi_DirectConcat.java
    """
    file_path = class_path.replace('.', '/') + '.java'
    return Path('src/main/java') / file_path'''
    
    new_path_func = '''def get_source_file_path(class_path):
    """
    Convert class path to source file path
    Try both JPAMB (src/main/java/) and Securibench (src/) structures
    """
    file_path = class_path.replace('.', '/') + '.java'
    
    # Try JPAMB structure first
    jpamb_path = Path('src/main/java') / file_path
    if jpamb_path.exists():
        return jpamb_path
    
    # Try Securibench structure
    securibench_path = Path('src') / file_path
    if securibench_path.exists():
        return securibench_path
    
    # Return JPAMB path for error message
    return jpamb_path'''
    
    if old_path_func in content:
        content = content.replace(old_path_func, new_path_func)
        print("✓ Patched get_source_file_path function")
    
    # Patch 2: Fix extract_method_body to handle servlet methods with throws clauses
    old_extract = '''def extract_method_body(source_code, method_name):
    """
    Extract the body of a specific method from Java source code
    """
    patterns = [
        rf'public\s+static\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
        rf'public\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
        rf'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+{method_name}\s*\(([^)]*)\)\s*\{{',
    ]'''
    
    new_extract = '''def extract_method_body(source_code, method_name):
    """
    Extract the body of a specific method from Java source code
    Enhanced to handle servlet methods with throws clauses
    """
    patterns = [
        rf'public\s+static\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*(?:throws\s+[^{{]*?)?\{{',
        rf'public\s+\w+\s+{method_name}\s*\(([^)]*)\)\s*(?:throws\s+[^{{]*?)?\{{',
        rf'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+{method_name}\s*\(([^)]*)\)\s*(?:throws\s+[^{{]*?)?\{{',
        rf'protected\s+void\s+{method_name}\s*\(([^)]*)\)\s*throws\s+[^{{]*\{{',
    ]'''
    
    if old_extract in content:
        content = content.replace(old_extract, new_extract)
        print("✓ Patched extract_method_body to handle servlet methods")
    
    # Write the patched version
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✓ Saved enhanced analyzer to: {output_file}")
    print()
    print("Test it with:")
    print(f"  python {output_file} securibench.micro.basic.Basic19.doGet")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python patch_analyzer_enhanced.py <input_analyzer.py> [output_analyzer.py]")
        print()
        print("Example:")
        print("  python patch_analyzer_enhanced.py my_analyzer_securibench.py")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file
    
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    patch_analyzer_enhanced(input_file, output_file)
