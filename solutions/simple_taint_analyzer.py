#!/usr/bin/env python3
"""
Minimal taint analyzer for SQL injection detection.

Uses variable-level taint tracking to detect SQL injection vulnerabilities
by tracking untrusted data flow from sources (e.g., getParameter()) to
SQL execution sinks (e.g., Statement.execute()).
"""

import logging
import re
import sys
from pathlib import Path
from typing import Dict

import jpamb
import tree_sitter
import tree_sitter_java

from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector

# Register analyzer with JPAMB
methodid = jpamb.getmethodid(
    "simple_taint_analyzer",
    "1.0",
    "DTU Compute Group 4",
    ["taint", "sql-injection", "dataflow"],
    for_science=True,
)

# Setup logging
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Initialize tree-sitter parser
JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
parser = tree_sitter.Parser(JAVA_LANGUAGE)

# Initialize source/sink detector
detector = SourceSinkDetector.default()


def extract_method_body(methodid: jpamb.jvm.AbsMethodID) -> tree_sitter.Node:
    """Extract the method body AST node from source file."""
    srcfile = jpamb.sourcefile(methodid).relative_to(Path.cwd())

    with open(srcfile, "rb") as f:
        log.debug("Parsing source file: %s", srcfile)
        tree = parser.parse(f.read())

    # Find class
    simple_classname = str(methodid.classname.name)
    class_q = tree_sitter.Query(
        JAVA_LANGUAGE,
        f"""
        (class_declaration
            name: ((identifier) @class-name
                   (#eq? @class-name "{simple_classname}"))) @class
        """,
    )

    for node in tree_sitter.QueryCursor(class_q).captures(tree.root_node)["class"]:
        break
    else:
        log.error(f"Could not find class {simple_classname} in {srcfile}")
        sys.exit(-1)

    # Find method
    method_name = methodid.extension.name
    method_q = tree_sitter.Query(
        JAVA_LANGUAGE,
        f"""
        (method_declaration name:
          ((identifier) @method-name (#eq? @method-name "{method_name}"))
        ) @method
        """,
    )

    for method_node in tree_sitter.QueryCursor(method_q).captures(node)["method"]:
        # Verify parameter count matches
        if p := method_node.child_by_field_name("parameters"):
            params = [c for c in p.children if c.type == "formal_parameter"]
            if len(params) == len(methodid.extension.params):
                break
    else:
        log.warning(f"Could not find method {method_name} in {simple_classname}")
        sys.exit(-1)

    # Get method body
    body = method_node.child_by_field_name("body")
    if not body or not body.text:
        log.error("Could not extract method body")
        sys.exit(-1)

    log.debug("Method body extracted successfully")
    return body


def analyze_taint_flow(body: tree_sitter.Node) -> bool:
    """
    Analyze taint flow through method body.

    Returns True if SQL injection vulnerability detected, False otherwise.
    """
    # Taint map: variable name -> TaintedValue
    taint_map: Dict[str, TaintedValue] = {}

    body_text = body.text.decode() if body.text else ""
    log.debug("Analyzing method body:\n%s", body_text)

    # Query for all local variable declarations and assignments
    var_decl_q = tree_sitter.Query(
        JAVA_LANGUAGE,
        """
        (local_variable_declaration
            declarator: (variable_declarator
                name: (identifier) @var-name
                value: (_) @var-value
            )
        ) @var-decl
        """
    )

    # Query for method invocations (sources and sinks)
    method_inv_q = tree_sitter.Query(
        JAVA_LANGUAGE,
        """
        (method_invocation
            name: (identifier) @method-name
        ) @method-inv
        """
    )

    # Phase 1: Detect string literals (trusted)
    for capture_name, nodes in tree_sitter.QueryCursor(var_decl_q).captures(body).items():
        if capture_name == "var-decl":
            for node in nodes:
                var_name_node = None
                var_value_node = None

                # Extract variable name and value
                for child in node.children:
                    if child.type == "variable_declarator":
                        var_name_node = child.child_by_field_name("name")
                        var_value_node = child.child_by_field_name("value")

                if var_name_node and var_value_node:
                    var_name = var_name_node.text.decode()
                    var_value_text = var_value_node.text.decode()

                    # Check if it's a string literal
                    if var_value_node.type == "string_literal":
                        log.debug(f"Found literal: {var_name} = {var_value_text}")
                        taint_map[var_name] = TaintedValue.trusted(var_value_text, source="literal")

                    # Check if it's a method call (might be a source)
                    elif var_value_node.type == "method_invocation":
                        method_name_text = extract_method_name(var_value_node)
                        if detector.is_source(method_name_text):
                            log.debug(f"Found source: {var_name} = {method_name_text}()")
                            source_type = detector.get_source_type(method_name_text)
                            taint_map[var_name] = TaintedValue.untrusted("user_input", source=source_type)
                        else:
                            # Unknown method call - assume safe for now
                            log.debug(f"Unknown method call: {method_name_text}")
                            taint_map[var_name] = TaintedValue.trusted(var_value_text)

                    # Check if it's a binary operation (e.g., concatenation)
                    elif var_value_node.type == "binary_expression":
                        result = analyze_binary_expression(var_value_node, taint_map)
                        log.debug(f"Binary expression result for {var_name}: tainted={result.is_tainted}")
                        taint_map[var_name] = result

    # Phase 2: Detect SQL execution sinks
    for capture_name, nodes in tree_sitter.QueryCursor(method_inv_q).captures(body).items():
        if capture_name == "method-inv":
            for node in nodes:
                method_name_text = extract_method_name(node)

                if detector.is_sink(method_name_text):
                    log.debug(f"Found sink: {method_name_text}()")

                    # Check arguments to the sink
                    args = node.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "identifier":
                                arg_name = arg.text.decode()
                                if arg_name in taint_map:
                                    if taint_map[arg_name].is_tainted:
                                        log.warning(f"VULNERABILITY: Tainted variable '{arg_name}' used in SQL sink!")
                                        return True
                            elif arg.type == "binary_expression":
                                # Inline concatenation in sink argument
                                result = analyze_binary_expression(arg, taint_map)
                                if result.is_tainted:
                                    log.warning(f"VULNERABILITY: Tainted expression used in SQL sink!")
                                    return True

    log.debug("No SQL injection vulnerability detected")
    return False


def extract_method_name(node: tree_sitter.Node) -> str:
    """Extract full method name from method invocation node."""
    method_name_parts = []

    # Get the method name
    for child in node.children:
        if child.type == "identifier":
            method_name_parts.append(child.text.decode())

    # Get object/class if present (for fully qualified names)
    obj = node.child_by_field_name("object")
    if obj:
        method_name_parts.insert(0, obj.text.decode())

    method_name = ".".join(method_name_parts)

    # Handle simplified test methods
    # getParameter() simulates HttpServletRequest.getParameter()
    if "getParameter" in method_name:
        return "javax.servlet.http.HttpServletRequest.getParameter"

    # execute() simulates Statement.execute()
    if method_name == "execute":
        return "java.sql.Statement.execute"

    return method_name


def analyze_binary_expression(node: tree_sitter.Node, taint_map: Dict[str, TaintedValue]) -> TaintedValue:
    """Analyze binary expression (e.g., string concatenation)."""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    operator = node.child_by_field_name("operator")

    if not left or not right:
        return TaintedValue.untrusted("unknown")

    # Get taint status of operands
    left_taint = get_taint_from_node(left, taint_map)
    right_taint = get_taint_from_node(right, taint_map)

    # For concatenation, apply taint transfer
    if operator and operator.text and b"+" in operator.text:
        return TaintTransfer.concat(left_taint, right_taint)

    # For other operations, conservative approach
    return TaintTransfer.concat(left_taint, right_taint)


def get_taint_from_node(node: tree_sitter.Node, taint_map: Dict[str, TaintedValue]) -> TaintedValue:
    """Get taint status from AST node."""
    if node.type == "string_literal":
        return TaintedValue.trusted(node.text.decode(), source="literal")
    elif node.type == "identifier":
        var_name = node.text.decode()
        return taint_map.get(var_name, TaintedValue.untrusted("unknown"))
    elif node.type == "method_invocation":
        method_name = extract_method_name(node)
        if detector.is_source(method_name):
            source_type = detector.get_source_type(method_name)
            return TaintedValue.untrusted("user_input", source=source_type)
        return TaintedValue.trusted("method_result")
    elif node.type == "binary_expression":
        return analyze_binary_expression(node, taint_map)
    else:
        # Unknown node type - conservative approach
        return TaintedValue.untrusted("unknown")


def main():
    """Main entry point."""
    body = extract_method_body(methodid)
    has_vulnerability = analyze_taint_flow(body)

    if has_vulnerability:
        print("sql injection;90%")
    else:
        print("ok;90%")

    sys.exit(0)


if __name__ == "__main__":
    main()
