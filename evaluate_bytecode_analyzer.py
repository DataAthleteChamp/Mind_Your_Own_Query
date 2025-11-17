#!/usr/bin/env python3
"""
Evaluation script for the bytecode taint analyzer.
Runs on all 50 test methods (25 vulnerable + 25 safe) from the SQLi test suite.
"""

import json
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class TestResult:
    """Result of running a single test case."""
    test_id: int
    name: str
    method_signature: str
    expected_vulnerable: bool
    actual_result: str
    detected_vulnerable: bool
    correct: bool
    category: str

    @property
    def is_true_positive(self) -> bool:
        return self.expected_vulnerable and self.detected_vulnerable

    @property
    def is_true_negative(self) -> bool:
        return not self.expected_vulnerable and not self.detected_vulnerable

    @property
    def is_false_positive(self) -> bool:
        return not self.expected_vulnerable and self.detected_vulnerable

    @property
    def is_false_negative(self) -> bool:
        return self.expected_vulnerable and not self.detected_vulnerable


def get_method_signature_from_bytecode(method_name: str) -> str:
    """
    Get the actual method signature from bytecode JSON file.

    Args:
        method_name: Method name like "jpamb.sqli.SQLi_DirectConcat.vulnerable"

    Returns:
        Full signature like "jpamb.sqli.SQLi_DirectConcat.vulnerable:(Ljava/lang/String;)V"
    """
    parts = method_name.split(".")
    class_name = ".".join(parts[:-1])
    method = parts[-1]

    # Convert class name to file path
    json_path = Path("target/decompiled") / (class_name.replace(".", "/") + ".json")

    if not json_path.exists():
        # Fallback to no parameters
        return f"{method_name}:()V"

    try:
        with open(json_path) as f:
            data = json.load(f)

        for method_data in data.get("methods", []):
            if method_data["name"] == method:
                # Build parameter signature
                params = []
                for param in method_data.get("params", []):
                    param_type = param.get("type", {})
                    kind = param_type.get("kind")

                    if kind == "class" or kind == "string":
                        # All reference/object types use 'A' in JPAMB format
                        params.append("A")
                    elif kind == "int":
                        params.append("I")
                    elif kind == "boolean":
                        params.append("Z")
                    elif kind == "byte":
                        params.append("B")
                    elif kind == "char":
                        params.append("C")
                    elif kind == "short":
                        params.append("S")
                    elif kind == "long":
                        params.append("J")
                    elif kind == "float":
                        params.append("F")
                    elif kind == "double":
                        params.append("D")
                    elif kind == "array":
                        # Arrays are '[' + element type
                        params.append("[A")  # Simplification: assume object arrays
                    else:
                        # Unknown type - skip (don't add to params)
                        continue

                # Build return type
                returns = method_data.get("returns", {})
                ret_kind = returns.get("kind")
                if ret_kind == "void":
                    ret_sig = "V"
                elif ret_kind == "class" or ret_kind == "string":
                    ret_sig = "A"  # Reference type
                elif ret_kind == "int":
                    ret_sig = "I"
                elif ret_kind == "boolean":
                    ret_sig = "Z"
                else:
                    ret_sig = "V"  # Default to void

                param_sig = "".join(params)
                return f"{method_name}:({param_sig}){ret_sig}"

        # Method not found, fallback
        return f"{method_name}:()V"

    except Exception:
        # Error reading file, fallback
        return f"{method_name}:()V"


def run_analyzer(method_signature: str) -> Tuple[str, bool]:
    """
    Run the bytecode analyzer on a method.

    Args:
        method_signature: Method name (e.g., "jpamb.sqli.SQLi_DirectConcat.vulnerable")

    Returns:
        Tuple of (full output, is_vulnerable)
    """
    # Our analyzer handles simple signatures directly via resolve_method_id()
    # No need to convert to full JVM bytecode format

    try:
        result = subprocess.run(
            ["python3", "solutions/bytecode_taint_analyzer.py", method_signature],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout.strip()

        # Parse output: "sql injection;90%" or "ok;90%"
        is_vulnerable = "sql injection" in output.lower()

        return output, is_vulnerable

    except subprocess.TimeoutExpired:
        return "TIMEOUT", False
    except Exception as e:
        return f"ERROR: {e}", False


def load_test_cases(test_cases_file: Path) -> List[dict]:
    """Load test case definitions from JSON."""
    with open(test_cases_file) as f:
        data = json.load(f)
    return data["test_cases"]


def run_evaluation(test_cases_file: Path) -> List[TestResult]:
    """Run full evaluation on all test cases."""
    test_cases = load_test_cases(test_cases_file)
    results = []

    total_methods = len(test_cases) * 2  # vulnerable + safe for each
    current = 0

    for test_case in test_cases:
        test_id = test_case["id"]
        name = test_case["name"]
        category = test_case["category"]

        # Test vulnerable method
        current += 1
        print(f"[{current}/{total_methods}] Testing {name}.vulnerable...", end=" ")
        vulnerable_method = test_case["vulnerable_method"]
        output, detected = run_analyzer(vulnerable_method)
        expected = test_case["expected_vulnerable"]
        correct = (detected == expected)

        results.append(TestResult(
            test_id=test_id,
            name=f"{name}_vulnerable",
            method_signature=vulnerable_method,
            expected_vulnerable=expected,
            actual_result=output,
            detected_vulnerable=detected,
            correct=correct,
            category=category
        ))

        status = "✅" if correct else "❌"
        print(f"{status} (expected: {'VULN' if expected else 'SAFE'}, got: {'VULN' if detected else 'SAFE'})")

        # Test safe method
        current += 1
        print(f"[{current}/{total_methods}] Testing {name}.safe...", end=" ")
        safe_method = test_case["safe_method"]
        output, detected = run_analyzer(safe_method)
        expected = test_case["expected_safe"]
        correct = (detected == expected)

        results.append(TestResult(
            test_id=test_id,
            name=f"{name}_safe",
            method_signature=safe_method,
            expected_vulnerable=expected,
            actual_result=output,
            detected_vulnerable=detected,
            correct=correct,
            category=category
        ))

        status = "✅" if correct else "❌"
        print(f"{status} (expected: {'VULN' if expected else 'SAFE'}, got: {'VULN' if detected else 'SAFE'})")

    return results


def calculate_metrics(results: List[TestResult]) -> dict:
    """Calculate precision, recall, F1-score, accuracy."""
    tp = sum(1 for r in results if r.is_true_positive)
    tn = sum(1 for r in results if r.is_true_negative)
    fp = sum(1 for r in results if r.is_false_positive)
    fn = sum(1 for r in results if r.is_false_negative)

    total = len(results)
    correct = tp + tn

    accuracy = (correct / total * 100) if total > 0 else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    return {
        "total": total,
        "correct": correct,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


def print_summary(results: List[TestResult], metrics: dict):
    """Print evaluation summary."""
    print("\n" + "=" * 80)
    print("BYTECODE TAINT ANALYZER - EVALUATION RESULTS")
    print("=" * 80)

    print(f"\nTotal test methods: {metrics['total']}")
    print(f"Correct: {metrics['correct']}/{metrics['total']} ({metrics['accuracy']:.1f}%)")

    print("\n--- Confusion Matrix ---")
    print(f"True Positives (TP):  {metrics['tp']:2d} - Vulnerable correctly detected")
    print(f"True Negatives (TN):  {metrics['tn']:2d} - Safe correctly identified")
    print(f"False Positives (FP): {metrics['fp']:2d} - Safe incorrectly flagged as vulnerable")
    print(f"False Negatives (FN): {metrics['fn']:2d} - Vulnerable incorrectly marked as safe")

    print("\n--- Performance Metrics ---")
    print(f"Accuracy:  {metrics['accuracy']:.1f}%")
    print(f"Precision: {metrics['precision']:.1f}%")
    print(f"Recall:    {metrics['recall']:.1f}%")
    print(f"F1-Score:  {metrics['f1']:.1f}%")

    # Category breakdown
    print("\n--- Results by Category ---")
    categories = {}
    for r in results:
        if r.category not in categories:
            categories[r.category] = {"correct": 0, "total": 0}
        categories[r.category]["total"] += 1
        if r.correct:
            categories[r.category]["correct"] += 1

    for category in sorted(categories.keys()):
        stats = categories[category]
        accuracy = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
        print(f"  {category:25s} {stats['correct']:2d}/{stats['total']:2d} ({accuracy:5.1f}%)")

    # Show failures if any
    failures = [r for r in results if not r.correct]
    if failures:
        print("\n--- Failed Test Cases ---")
        for r in failures:
            expected = "VULN" if r.expected_vulnerable else "SAFE"
            got = "VULN" if r.detected_vulnerable else "SAFE"
            print(f"  ❌ {r.name:40s} Expected: {expected}, Got: {got}")
    else:
        print("\n🎉 All test cases passed!")

    print("\n" + "=" * 80)


def save_results(results: List[TestResult], metrics: dict, output_file: Path):
    """Save results to JSON file."""
    data = {
        "metrics": metrics,
        "results": [
            {
                "test_id": r.test_id,
                "name": r.name,
                "method_signature": r.method_signature,
                "category": r.category,
                "expected_vulnerable": r.expected_vulnerable,
                "detected_vulnerable": r.detected_vulnerable,
                "correct": r.correct,
                "actual_result": r.actual_result
            }
            for r in results
        ]
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nResults saved to: {output_file}")


def main():
    """Main evaluation entry point."""
    test_cases_file = Path("sqli-test-suite/test_cases.json")

    if not test_cases_file.exists():
        print(f"Error: Test cases file not found: {test_cases_file}")
        sys.exit(1)

    print("Starting bytecode taint analyzer evaluation...")
    print(f"Test cases: {test_cases_file}")
    print()

    # Run evaluation
    results = run_evaluation(test_cases_file)

    # Calculate metrics
    metrics = calculate_metrics(results)

    # Print summary
    print_summary(results, metrics)

    # Save results
    output_file = Path("bytecode_evaluation_results.json")
    save_results(results, metrics, output_file)


if __name__ == "__main__":
    main()
