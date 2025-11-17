#!/usr/bin/env python3
"""
Extract method signatures from compiled bytecode JSON files.
"""

import json
from pathlib import Path


def extract_signatures(json_file: Path) -> list[str]:
    """Extract all method signatures from a bytecode JSON file."""
    with open(json_file) as f:
        data = json.load(f)

    signatures = []
    class_name = data["name"].replace("/", ".")

    for method in data.get("methods", []):
        method_name = method["name"]

        # Build parameter signature
        params = []
        for param in method.get("params", []):
            param_type = param.get("type", {})
            kind = param_type.get("kind")

            if kind == "class":
                type_name = param_type.get("name", "")
                params.append(f"L{type_name};")
            elif kind == "int":
                params.append("I")
            elif kind == "boolean":
                params.append("Z")
            elif kind == "string":
                params.append("Ljava/lang/String;")
            else:
                params.append("?")  # Unknown type

        # Build return type
        returns = method.get("returns", {})
        ret_kind = returns.get("kind")
        if ret_kind == "void":
            ret_sig = "V"
        elif ret_kind == "class":
            ret_name = returns.get("name", "")
            ret_sig = f"L{ret_name};"
        else:
            ret_sig = "V"  # Default to void

        # Build full signature
        param_sig = "".join(params)
        full_sig = f"{class_name}.{method_name}:({param_sig}){ret_sig}"

        signatures.append(full_sig)

    return signatures


def main():
    """Extract signatures from all SQLi test cases."""
    sqli_dir = Path("target/decompiled/jpamb/sqli")

    if not sqli_dir.exists():
        print(f"Error: Directory not found: {sqli_dir}")
        return

    print("Method signatures for SQLi test cases:")
    print("=" * 80)

    for json_file in sorted(sqli_dir.glob("SQLi_*.json")):
        class_name = json_file.stem
        print(f"\n{class_name}:")

        signatures = extract_signatures(json_file)
        for sig in signatures:
            method_name = sig.split(".")[-1].split(":")[0]
            if method_name in ["vulnerable", "safe"]:
                print(f"  {sig}")


if __name__ == "__main__":
    main()
