#!/usr/bin/env python3
"""
Securibench Micro Adapter for my_analyzer.py
Runs the SQL injection analyzer on Securibench Micro test cases
"""

import sys
import os
import re
import subprocess
import json
from pathlib import Path
from datetime import datetime

def find_java_files(src_dir):
    """Find all Java test files in Securibench"""
    java_files = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.java') and not file in ['BasicTestCase.java', 'MicroTestCase.java']:
                java_files.append(Path(root) / file)
    return java_files

def extract_vulnerability_count(java_file):
    """Extract expected vulnerability count from Java file"""
    content = java_file.read_text(encoding='utf-8', errors='ignore')
    
    # Look for @servlet vuln_count annotation
    match = re.search(r'@servlet vuln_count\s*=\s*["\']?(\d+)["\']?', content)
    if match:
        return int(match.group(1))
    
    # Look for getVulnerabilityCount() method
    match = re.search(r'public int getVulnerabilityCount\(\)\s*\{\s*return (\d+);', content)
    if match:
        return int(match.group(1))
    
    return 0

def is_sql_injection_test(java_file):
    """Check if this is a SQL injection test"""
    content = java_file.read_text(encoding='utf-8', errors='ignore')
    
    # Check for SQL-related imports or code
    sql_indicators = [
        'java.sql',
        'prepareStatement',
        'executeQuery',
        'executeUpdate',
        'createStatement',
        'SQL injection'
    ]
    
    return any(indicator in content for indicator in sql_indicators)

def get_test_category(java_file):
    """Get category from file path"""
    parts = java_file.parts
    if 'basic' in parts:
        return 'basic'
    elif 'arrays' in parts:
        return 'arrays'
    elif 'collections' in parts:
        return 'collections'
    elif 'inter' in parts:
        return 'inter'
    elif 'aliasing' in parts:
        return 'aliasing'
    elif 'datastructures' in parts:
        return 'datastructures'
    elif 'factories' in parts:
        return 'factories'
    elif 'pred' in parts:
        return 'pred'
    elif 'sanitizers' in parts:
        return 'sanitizers'
    elif 'session' in parts:
        return 'session'
    elif 'strong_updates' in parts:
        return 'strong_updates'
    elif 'reflection' in parts:
        return 'reflection'
    return 'other'

def run_analyzer(analyzer_path, class_signature):
    """Run my_analyzer.py on a method"""
    try:
        result = subprocess.run(
            ['python', str(analyzer_path), class_signature],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Parse output: "SQL injection;95" or "ok;70"
        stdout = result.stdout.strip()
        for line in stdout.split('\n'):
            if ';' in line:
                parts = line.split(';')
                outcome = parts[0].strip()
                confidence = int(parts[1].strip()) if len(parts) > 1 else 0
                return outcome, confidence
        
        return "error", 0
    except subprocess.TimeoutExpired:
        return "timeout", 0
    except Exception as e:
        print(f"Error running analyzer: {e}", file=sys.stderr)
        return "error", 0

def analyze_securibench(securibench_root, analyzer_path):
    """Analyze all Securibench test cases"""
    
    src_dir = Path(securibench_root) / 'src'
    if not src_dir.exists():
        print(f"Error: Source directory not found: {src_dir}")
        return None
    
    print("=" * 70)
    print("Securibench Micro Analysis with my_analyzer.py")
    print("=" * 70)
    print()
    
    java_files = find_java_files(src_dir)
    print(f"Found {len(java_files)} test files")
    
    # Filter for SQL injection tests
    sql_tests = [(f, extract_vulnerability_count(f)) for f in java_files if is_sql_injection_test(f)]
    print(f"Found {len(sql_tests)} SQL injection test cases")
    print()
    
    results = []
    detected_count = 0
    total_expected_vulns = 0
    
    for idx, (java_file, expected_vulns) in enumerate(sql_tests, 1):
        # Get class name
        class_name = java_file.stem
        
        # Get package from file path
        rel_path = java_file.relative_to(src_dir)
        package = '.'.join(rel_path.parts[:-1])
        full_class = f"{package}.{class_name}"
        
        # Method signature for doGet
        method_sig = f"{full_class}.doGet"
        
        print(f"[{idx}/{len(sql_tests)}] Testing: {class_name}")
        print(f"  Package: {package}")
        print(f"  Expected vulnerabilities: {expected_vulns}")
        
        # Run analyzer
        outcome, confidence = run_analyzer(analyzer_path, method_sig)
        
        # Check if detected
        detected = outcome == "SQL injection"
        
        print(f"  Analyzer result: {outcome} (confidence: {confidence})")
        print(f"  Detection: {'✓ PASS' if (detected and expected_vulns > 0) or (not detected and expected_vulns == 0) else '✗ FAIL'}")
        print()
        
        if detected:
            detected_count += 1
        
        total_expected_vulns += expected_vulns
        
        results.append({
            'test_name': class_name,
            'package': package,
            'category': get_test_category(java_file),
            'expected_vulns': expected_vulns,
            'detected': detected,
            'outcome': outcome,
            'confidence': confidence,
            'correct': (detected and expected_vulns > 0) or (not detected and expected_vulns == 0)
        })
    
    # Calculate statistics
    correct = sum(1 for r in results if r['correct'])
    total = len(results)
    accuracy = (correct / total * 100) if total > 0 else 0
    
    # Detection rate (of tests that should have vulnerabilities)
    should_detect = [r for r in results if r['expected_vulns'] > 0]
    detected_vulns = sum(1 for r in should_detect if r['detected'])
    detection_rate = (detected_vulns / len(should_detect) * 100) if should_detect else 0
    
    # False positive rate
    should_not_detect = [r for r in results if r['expected_vulns'] == 0]
    false_positives = sum(1 for r in should_not_detect if r['detected'])
    fp_rate = (false_positives / len(should_not_detect) * 100) if should_not_detect else 0
    
    # Print summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print(f"Total SQL Injection Tests: {total}")
    print(f"Tests with Expected Vulnerabilities: {len(should_detect)}")
    print(f"Tests without Expected Vulnerabilities: {len(should_not_detect)}")
    print()
    print(f"Overall Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    print(f"Detection Rate: {detected_vulns}/{len(should_detect)} ({detection_rate:.1f}%)")
    print(f"False Positive Rate: {false_positives}/{len(should_not_detect)} ({fp_rate:.1f}%)")
    print()
    
    # Category breakdown
    categories = {}
    for r in results:
        cat = r['category']
        if cat not in categories:
            categories[cat] = {'total': 0, 'correct': 0}
        categories[cat]['total'] += 1
        if r['correct']:
            categories[cat]['correct'] += 1
    
    print("Category Breakdown:")
    for cat, stats in sorted(categories.items()):
        pct = (stats['correct'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"  {cat}: {stats['correct']}/{stats['total']} ({pct:.1f}%)")
    print()
    
    # Save results
    report = {
        'timestamp': datetime.now().isoformat(),
        'securibench_root': str(securibench_root),
        'analyzer': str(analyzer_path),
        'statistics': {
            'total_tests': total,
            'correct': correct,
            'accuracy': accuracy,
            'detection_rate': detection_rate,
            'false_positive_rate': fp_rate,
            'tests_with_vulns': len(should_detect),
            'detected_vulns': detected_vulns,
            'tests_without_vulns': len(should_not_detect),
            'false_positives': false_positives
        },
        'categories': categories,
        'results': results
    }
    
    output_file = Path('securibench_results.json')
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Results saved to: {output_file}")
    
    return report

def main():
    if len(sys.argv) < 3:
        print("Usage: python securibench_adapter.py <securibench_root> <my_analyzer.py>")
        print()
        print("Example:")
        print("  python securibench_adapter.py C:\\Users\\lando\\securibench-micro C:\\Users\\lando\\Mind_Your_Own_Query\\my_analyzer.py")
        sys.exit(1)
    
    securibench_root = Path(sys.argv[1])
    analyzer_path = Path(sys.argv[2])
    
    if not securibench_root.exists():
        print(f"Error: Securibench root not found: {securibench_root}")
        sys.exit(1)
    
    if not analyzer_path.exists():
        print(f"Error: Analyzer not found: {analyzer_path}")
        sys.exit(1)
    
    analyze_securibench(securibench_root, analyzer_path)

if __name__ == '__main__':
    main()
