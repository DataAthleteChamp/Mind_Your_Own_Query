#!/usr/bin/env python3
"""Patch my_analyzer.py to work with Securibench directory structure"""

import sys
from pathlib import Path

def patch_analyzer(input_file, output_file):
    """Patch the analyzer to handle both directory structures"""
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # The old function to replace
    old_function = '''def get_source_file_path(class_path):
    """
    Convert class path to source file path
    jpamb.sqli.SQLi_DirectConcat -> src/main/java/jpamb/sqli/SQLi_DirectConcat.java
    """
    file_path = class_path.replace('.', '/') + '.java'
    return Path('src/main/java') / file_path'''
    
    # The new function that tries both paths
    new_function = '''def get_source_file_path(class_path):
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
    
    # Replace the function
    if old_function in content:
        content = content.replace(old_function, new_function)
        print(f"✓ Patched get_source_file_path function")
    else:
        print("✗ Warning: Could not find function to patch")
        print("  The analyzer may already be patched or have a different structure")
    
    # Write the patched version
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✓ Saved patched analyzer to: {output_file}")
    print()
    print("Test it with:")
    print(f"  python {output_file} securibench.micro.basic.Basic19.doGet")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python patch_analyzer.py <input_analyzer.py> <output_analyzer.py>")
        print()
        print("Example:")
        print("  python patch_analyzer.py my_analyzer.py my_analyzer_securibench.py")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    patch_analyzer(input_file, output_file)
