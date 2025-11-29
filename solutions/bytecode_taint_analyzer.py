#!/usr/bin/env python3
"""
Bytecode-based taint analyzer for SQL injection detection.

Uses abstract interpretation on JVM bytecode to track taint flow from
untrusted sources (method parameters, HTTP requests) to SQL execution sinks.

Advantages over source-based analysis:
- Finite set of JVM opcodes (~12 core operations)
- All string operations become invokevirtual calls
- Type information explicit in method signatures
- Canonical representation (no syntactic variations)
"""

import logging
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path

import jpamb
from jpamb import jvm
from jpamb.model import Suite
from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector

# Setup logging
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING)  # Change to WARNING to reduce noise

# Initialize source/sink detector
detector = SourceSinkDetector.default()


# ============================================================================
# Method Resolution
# ============================================================================

def resolve_method_id(method_signature: str, suite: Suite) -> Optional[jvm.AbsMethodID]:
    """
    Resolve a simple method signature to a JPAMB AbsMethodID.

    Args:
        method_signature: Simple format like "jpamb.sqli.SQLi_DirectConcat.vulnerable"
        suite: JPAMB Suite instance

    Returns:
        AbsMethodID if found, None otherwise

    Example:
        >>> resolve_method_id("jpamb.sqli.SQLi_DirectConcat.vulnerable", suite)
        jpamb.sqli.SQLi_DirectConcat.vulnerable:(java.lang.String)void
    """
    # Parse the signature
    # Handle both formats:
    #   1. "jpamb.sqli.SQLi_DirectConcat.vulnerable"
    #   2. "jpamb.sqli.SQLi_DirectConcat.vulnerable:(A)V"

    # Strip signature part if present
    if ':' in method_signature:
        base_signature = method_signature.split(':')[0]
    else:
        base_signature = method_signature

    parts = base_signature.rsplit('.', 1)
    if len(parts) != 2:
        log.error(f"Invalid method signature format: {method_signature}")
        return None

    class_name, method_name = parts
    log.debug(f"Looking for class: {class_name}, method: {method_name}")

    # Find matching class
    try:
        # Parse class name to ClassName object
        class_obj = jvm.ClassName.decode(class_name)

        # Get class info from decompiled JSON
        class_info = suite.findclass(class_obj)

        # Find methods with matching name (methods is a list of dicts)
        matching_methods = [
            method_dict for method_dict in class_info['methods']
            if method_dict['name'] == method_name
        ]

        if not matching_methods:
            log.error(f"No method named '{method_name}' found in class {class_name}")
            return None

        if len(matching_methods) > 1:
            log.warning(f"Multiple methods named '{method_name}' found, using first one")

        # Build AbsMethodID from the method dict
        method_dict = matching_methods[0]

        # Convert params to ParameterType
        param_types = []
        for param in method_dict['params']:
            param_type = jvm.Type.from_json(param['type'])
            param_types.append(param_type)

        # Convert return type
        return_type = jvm.Type.from_json(method_dict['returns']['type']) if method_dict['returns']['type'] else None

        # Build MethodID - params must be ParameterType(tuple)
        method_ext = jvm.MethodID(
            name=method_name,
            params=jvm.ParameterType(tuple(param_types)),  # ParameterType takes a tuple
            return_type=return_type
        )

        # Build AbsMethodID
        method_id = jvm.AbsMethodID(class_obj, method_ext)

        log.info(f"Resolved to: {method_id}")
        return method_id

    except Exception as e:
        log.error(f"Error resolving method: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================================
# Abstract State Components
# ============================================================================

@dataclass
class HeapObject:
    """
    Abstract heap object for tracking taint state of objects (e.g., StringBuilder).

    Represents objects created with 'new' instruction.
    Tracks taint state and any appended values.
    """
    class_name: str
    taint: TaintedValue
    appended_values: List[TaintedValue] = field(default_factory=list)

    def is_string_builder(self) -> bool:
        """Check if this is a StringBuilder or StringBuffer"""
        return ("StringBuilder" in self.class_name or
                "StringBuffer" in self.class_name)

    def append(self, value: TaintedValue) -> None:
        """Append a value (for StringBuilder/StringBuffer)"""
        self.appended_values.append(value)
        # Update our taint if we're appending tainted data
        if value.is_tainted:
            self.taint = TaintTransfer.concat(self.taint, value)

    def to_string(self) -> TaintedValue:
        """Convert to string (for StringBuilder.toString())"""
        if self.appended_values:
            return TaintTransfer.concat(*self.appended_values)
        return self.taint

    def __repr__(self):
        taint_marker = "⚠️" if self.taint.is_tainted else "✓"
        return f"<{self.class_name} {taint_marker}>"


@dataclass
class TaintValue:
    """
    Taint value that can represent either a concrete value or a heap reference.

    This is what we track on the JVM stack and in local variables.

    TAJ-Style String Carriers:
    - StringBuilder/StringBuffer are treated as primitives (not heap objects)
    - is_string_carrier flag marks these special values
    - carrier_taint accumulates taint from all append() operations
    """
    tainted_value: TaintedValue
    heap_ref: Optional[int] = None  # Reference to HeapObject if this is an object
    # TAJ-style string carrier support
    is_string_carrier: bool = False
    carrier_taint: Optional[TaintedValue] = None

    @classmethod
    def from_tainted(cls, tv: TaintedValue) -> "TaintValue":
        """Create from TaintedValue"""
        return cls(tainted_value=tv, heap_ref=None)

    @classmethod
    def from_heap_ref(cls, ref: int, heap: Dict[int, HeapObject]) -> "TaintValue":
        """Create from heap reference"""
        obj = heap[ref]
        return cls(tainted_value=obj.taint, heap_ref=ref)

    @classmethod
    def trusted(cls, value, source="literal") -> "TaintValue":
        """Create trusted value"""
        return cls(tainted_value=TaintedValue.trusted(value, source=source))

    @classmethod
    def untrusted(cls, value, source="user_input") -> "TaintValue":
        """Create untrusted value"""
        return cls(tainted_value=TaintedValue.untrusted(value, source=source))

    @classmethod
    def string_carrier(cls, initial_taint: TaintedValue) -> "TaintValue":
        """
        Create a TAJ-style string carrier (StringBuilder/StringBuffer).

        String carriers are treated as primitives, not heap objects.
        Taint accumulates in carrier_taint as values are appended.
        """
        return cls(
            tainted_value=initial_taint,
            heap_ref=None,
            is_string_carrier=True,
            carrier_taint=initial_taint
        )

    def accumulate_taint(self, new_taint: TaintedValue) -> None:
        """
        Accumulate taint for string carrier (TAJ approach).

        This is used when append() is called on a StringBuilder/StringBuffer.
        """
        if self.is_string_carrier:
            if self.carrier_taint:
                self.carrier_taint = TaintTransfer.concat(self.carrier_taint, new_taint)
            else:
                self.carrier_taint = new_taint
            # Also update tainted_value to keep it in sync
            self.tainted_value = self.carrier_taint

    @property
    def is_tainted(self) -> bool:
        return self.tainted_value.is_tainted

    def __repr__(self):
        marker = "⚠️" if self.is_tainted else "✓"
        if self.heap_ref is not None:
            return f"TaintValue({marker} ref={self.heap_ref})"
        return f"TaintValue({marker} {self.tainted_value.value})"


@dataclass
class AbstractState:
    """
    Abstract state for taint analysis.

    Represents the state of the JVM at a specific program point:
    - stack: Operand stack
    - locals: Local variable table (parameters + local variables)
    - heap: Abstract heap for tracking objects
    - pc: Program counter
    - vulnerability_detected: Flag indicating if SQL injection found
    """
    stack: List[TaintValue]
    locals: Dict[int, TaintValue]
    heap: Dict[int, HeapObject]
    pc: int
    next_heap_addr: int = 0
    vulnerability_detected: bool = False

    @classmethod
    def initial(cls, method: jvm.AbsMethodID) -> "AbstractState":
        """
        Create initial state for method.

        All method parameters are marked as UNTRUSTED (they come from external sources).
        """
        locals = {}
        param_count = len(method.extension.params)

        # Mark all parameters as UNTRUSTED
        for i in range(param_count):
            locals[i] = TaintValue.untrusted(
                f"param_{i}",
                source="method_parameter"
            )

        log.debug(f"Initial state: {param_count} parameters marked as UNTRUSTED")

        return cls(
            stack=[],
            locals=locals,
            heap={},
            pc=0,
            next_heap_addr=1000
        )

    def allocate_heap_object(self, class_name: str) -> int:
        """Allocate new object in abstract heap"""
        addr = self.next_heap_addr
        self.next_heap_addr += 1
        self.heap[addr] = HeapObject(
            class_name=class_name,
            taint=TaintedValue.trusted("", source="new_object")
        )
        log.debug(f"Allocated {class_name} at heap addr {addr}")
        return addr

    def push(self, value: TaintValue) -> None:
        """Push value onto stack"""
        self.stack.append(value)

    def pop(self) -> TaintValue:
        """Pop value from stack"""
        if not self.stack:
            raise RuntimeError(f"Stack underflow at pc={self.pc}")
        return self.stack.pop()

    def peek(self) -> TaintValue:
        """Peek at top of stack without popping"""
        if not self.stack:
            raise RuntimeError(f"Stack underflow at pc={self.pc}")
        return self.stack[-1]

    def __repr__(self):
        return f"<State pc={self.pc} stack={len(self.stack)} locals={len(self.locals)} heap={len(self.heap)}>"

    def copy(self) -> "AbstractState":
        """Create a deep copy of the state for branch exploration"""
        return AbstractState(
            stack=list(self.stack),
            locals=dict(self.locals),
            heap=dict(self.heap),
            pc=self.pc,
            next_heap_addr=self.next_heap_addr,
            vulnerability_detected=self.vulnerability_detected
        )

    @staticmethod
    def join(state1: "AbstractState", state2: "AbstractState") -> "AbstractState":
        """
        Join two abstract states (lattice join operation).

        For taint analysis: if a variable is tainted in ANY predecessor,
        it must be considered tainted at the join point.

        This is the ⊔ operation: TRUSTED ⊔ UNTRUSTED = UNTRUSTED
        """
        # Merge locals: if tainted in either, result is tainted
        merged_locals = {}
        all_keys = set(state1.locals.keys()) | set(state2.locals.keys())
        for key in all_keys:
            val1 = state1.locals.get(key)
            val2 = state2.locals.get(key)
            if val1 is None:
                merged_locals[key] = val2
            elif val2 is None:
                merged_locals[key] = val1
            elif val1.is_tainted or val2.is_tainted:
                # Join: if either is tainted, result is tainted
                merged_locals[key] = TaintValue.untrusted("joined", source="control_flow_join")
            else:
                merged_locals[key] = val1

        # For stack: at join points, stacks should be same height
        # Use conservative approach - if either is tainted, result is tainted
        merged_stack = []
        max_len = max(len(state1.stack), len(state2.stack))
        for i in range(max_len):
            val1 = state1.stack[i] if i < len(state1.stack) else None
            val2 = state2.stack[i] if i < len(state2.stack) else None
            if val1 is None:
                merged_stack.append(val2)
            elif val2 is None:
                merged_stack.append(val1)
            elif val1.is_tainted or val2.is_tainted:
                merged_stack.append(TaintValue.untrusted("joined", source="control_flow_join"))
            else:
                merged_stack.append(val1)

        # Vulnerability detected if detected in either path
        vuln = state1.vulnerability_detected or state2.vulnerability_detected

        return AbstractState(
            stack=merged_stack,
            locals=merged_locals,
            heap={**state1.heap, **state2.heap},
            pc=state1.pc,  # PC at join point
            next_heap_addr=max(state1.next_heap_addr, state2.next_heap_addr),
            vulnerability_detected=vuln
        )

    def __eq__(self, other: "AbstractState") -> bool:
        """Check if two states are equal (for fixed-point detection)"""
        if not isinstance(other, AbstractState):
            return False
        # Compare taint status of locals
        if set(self.locals.keys()) != set(other.locals.keys()):
            return False
        for key in self.locals:
            if self.locals[key].is_tainted != other.locals.get(key, TaintValue.trusted("")).is_tainted:
                return False
        return True

    def __hash__(self):
        return hash(tuple((k, v.is_tainted) for k, v in sorted(self.locals.items())))


# ============================================================================
# Control Flow Graph (CFG)
# ============================================================================

@dataclass
class BasicBlock:
    """
    A basic block in the control flow graph.

    A basic block is a sequence of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No branches except at the end
    """
    id: int                          # Block identifier (start offset)
    start_offset: int                # First instruction offset
    end_offset: int                  # Last instruction offset (inclusive)
    instructions: List[jvm.Opcode]   # Instructions in this block
    successors: List[int] = field(default_factory=list)    # Successor block IDs
    predecessors: List[int] = field(default_factory=list)  # Predecessor block IDs

    def __repr__(self):
        return f"BB{self.id}[{self.start_offset}-{self.end_offset}] -> {self.successors}"


def build_cfg(opcodes: List[jvm.Opcode]) -> Dict[int, BasicBlock]:
    """
    Build a Control Flow Graph from bytecode opcodes.

    Algorithm:
    1. Identify leaders (block start points):
       - First instruction
       - Target of any branch
       - Instruction after any branch
    2. Create basic blocks between leaders
    3. Connect blocks with edges based on control flow

    Returns:
        Dictionary mapping block start offset to BasicBlock
    """
    if not opcodes:
        return {}

    # Build offset -> opcode index mapping
    offset_to_idx = {op.offset: i for i, op in enumerate(opcodes)}

    # Build index -> offset mapping (for branch targets)
    # NOTE: In jpamb, branch targets are instruction INDICES, not byte offsets
    idx_to_offset = {i: op.offset for i, op in enumerate(opcodes)}

    # Step 1: Identify leaders (by instruction index)
    leaders = {0}  # First instruction is always a leader

    for i, op in enumerate(opcodes):
        if isinstance(op, (jvm.Goto, jvm.If, jvm.Ifz)):
            # Target of branch is a leader (target is instruction INDEX)
            target_idx = op.target
            if 0 <= target_idx < len(opcodes):
                leaders.add(target_idx)
            # Instruction after branch is a leader (fall-through)
            if i + 1 < len(opcodes):
                leaders.add(i + 1)
        elif isinstance(op, jvm.Return):
            # Instruction after return is a leader (if any)
            if i + 1 < len(opcodes):
                leaders.add(i + 1)

    # Step 2: Create basic blocks
    sorted_leaders = sorted(leaders)
    blocks: Dict[int, BasicBlock] = {}

    for i, leader_idx in enumerate(sorted_leaders):
        # Find end of this block
        if i + 1 < len(sorted_leaders):
            end_idx = sorted_leaders[i + 1] - 1
        else:
            end_idx = len(opcodes) - 1

        block_instructions = opcodes[leader_idx:end_idx + 1]
        if block_instructions:
            start_offset = block_instructions[0].offset
            end_offset = block_instructions[-1].offset
            blocks[start_offset] = BasicBlock(
                id=start_offset,
                start_offset=start_offset,
                end_offset=end_offset,
                instructions=block_instructions
            )

    # Step 3: Connect blocks with edges
    for offset, block in blocks.items():
        if not block.instructions:
            continue

        last_instr = block.instructions[-1]
        last_idx = offset_to_idx.get(last_instr.offset, -1)

        if isinstance(last_instr, jvm.Goto):
            # Unconditional jump - only successor is target
            # Convert target index to offset
            target_idx = last_instr.target
            if 0 <= target_idx < len(opcodes):
                target_offset = idx_to_offset[target_idx]
                if target_offset in blocks:
                    block.successors.append(target_offset)
                    blocks[target_offset].predecessors.append(offset)

        elif isinstance(last_instr, (jvm.If, jvm.Ifz)):
            # Conditional branch - two successors: target and fall-through
            # Target (branch taken) - convert index to offset
            target_idx = last_instr.target
            if 0 <= target_idx < len(opcodes):
                target_offset = idx_to_offset[target_idx]
                if target_offset in blocks:
                    block.successors.append(target_offset)
                    blocks[target_offset].predecessors.append(offset)
            # Fall-through (branch not taken)
            if last_idx + 1 < len(opcodes):
                fall_through_offset = opcodes[last_idx + 1].offset
                if fall_through_offset in blocks:
                    block.successors.append(fall_through_offset)
                    blocks[fall_through_offset].predecessors.append(offset)

        elif isinstance(last_instr, jvm.Return):
            # Return - no successors
            pass

        else:
            # Normal instruction - fall through to next block
            if last_idx + 1 < len(opcodes):
                fall_through_offset = opcodes[last_idx + 1].offset
                if fall_through_offset in blocks:
                    block.successors.append(fall_through_offset)
                    blocks[fall_through_offset].predecessors.append(offset)

    log.debug(f"Built CFG with {len(blocks)} basic blocks")
    for offset, block in sorted(blocks.items()):
        log.debug(f"  {block}")

    return blocks


# ============================================================================
# Method Signature Matching
# ============================================================================

class MethodMatcher:
    """
    Matches method signatures to identify sources, sinks, and taint-preserving operations.

    This is the key to bytecode analysis: all string operations become method calls,
    so we just need to match method signatures.
    """

    # Known untrusted sources
    SOURCES = {
        "javax.servlet.http.HttpServletRequest.getParameter",
        "javax.servlet.http.HttpServletRequest.getHeader",
        "java.io.BufferedReader.readLine",
        "java.net.URLConnection.getInputStream",
    }

    # SQL execution sinks (fully qualified JDBC methods only)
    SINKS = {
        "java.sql.Statement.execute",
        "java.sql.Statement.executeQuery",
        "java.sql.Statement.executeUpdate",
        "java.sql.Connection.prepareStatement",
    }

    # Methods that preserve taint (string operations)
    TAINT_PRESERVING = {
        "java.lang.String.concat",
        "java.lang.String.trim",
        "java.lang.String.toUpperCase",
        "java.lang.String.toLowerCase",
        "java.lang.String.substring",
        "java.lang.String.replace",
        "java.lang.String.replaceAll",
        "java.lang.String.format",          # String.format() preserves taint
        "java.lang.String.join",            # String.join() preserves taint
        "java.lang.StringBuilder.append",
        "java.lang.StringBuffer.append",
    }

    @classmethod
    def is_source(cls, method: jvm.AbsMethodID) -> bool:
        """Check if method is an untrusted source (fully qualified signatures only)"""
        method_str = str(method)
        # Normalize slashes to dots for comparison (bytecode uses java/lang/String, we use java.lang.String)
        method_str_normalized = method_str.replace("/", ".")
        return any(source in method_str_normalized for source in cls.SOURCES)

    @classmethod
    def is_sink(cls, method: jvm.AbsMethodID) -> bool:
        """Check if method is a SQL sink"""
        method_str = str(method)
        # Normalize slashes to dots for comparison (bytecode uses java/sql/Statement, we use java.sql.Statement)
        method_str_normalized = method_str.replace("/", ".")
        return any(sink in method_str_normalized for sink in cls.SINKS)

    @classmethod
    def is_taint_preserving(cls, method: jvm.AbsMethodID) -> bool:
        """Check if method preserves taint"""
        method_str = str(method)
        # Normalize slashes to dots for comparison
        method_str_normalized = method_str.replace("/", ".")
        return any(op in method_str_normalized for op in cls.TAINT_PRESERVING)

    @classmethod
    def is_string_builder_tostring(cls, method: jvm.AbsMethodID) -> bool:
        """Check if method is StringBuilder.toString()"""
        method_str = str(method)
        # Normalize slashes to dots for comparison
        method_str_normalized = method_str.replace("/", ".")
        return ("StringBuilder.toString" in method_str_normalized or
                "StringBuffer.toString" in method_str_normalized)


# ============================================================================
# Transfer Functions (Core Bytecode Operations)
# ============================================================================

def transfer_push(opcode: jvm.Push, state: AbstractState) -> AbstractState:
    """
    Handle push (ldc) instruction.

    All constants are TRUSTED (they're literals in the bytecode).
    """
    value = opcode.value
    log.debug(f"  PUSH {value} → TRUSTED")

    state.push(TaintValue.trusted(value.value, source="constant"))
    state.pc += 1
    return state


def transfer_load(opcode: jvm.Load, state: AbstractState) -> AbstractState:
    """
    Handle load instruction (aload, iload, etc.).

    Load from local variable table onto stack.
    """
    index = opcode.index
    if index not in state.locals:
        # Unknown local → assume UNTRUSTED for soundness
        log.debug(f"  LOAD local[{index}] → UNKNOWN (assuming UNTRUSTED for safety)")
        state.push(TaintValue.untrusted("unknown", source="unknown_local"))
    else:
        value = state.locals[index]
        log.debug(f"  LOAD local[{index}] → {value}")
        state.push(value)

    state.pc += 1
    return state


def transfer_store(opcode: jvm.Store, state: AbstractState) -> AbstractState:
    """
    Handle store instruction (astore, istore, etc.).

    Pop from stack and store to local variable table.
    """
    index = opcode.index
    value = state.pop()
    log.debug(f"  STORE local[{index}] ← {value}")

    state.locals[index] = value
    state.pc += 1
    return state


def transfer_new(opcode: jvm.New, state: AbstractState) -> AbstractState:
    """
    Handle new instruction.

    TAJ-style: StringBuilder/StringBuffer are treated as string carriers (primitives).
    Other objects are allocated in abstract heap.
    """
    class_name = str(opcode.classname)
    log.debug(f"  NEW {class_name}")

    # TAJ-style: StringBuilder/StringBuffer are string carriers (not heap objects)
    if "StringBuilder" in class_name or "StringBuffer" in class_name:
        initial_taint = TaintedValue.trusted("empty", source="new_stringbuilder")
        carrier = TaintValue.string_carrier(initial_taint)
        log.debug(f"    → Created string carrier (TAJ-style)")
        state.push(carrier)
    else:
        # Regular heap allocation for other objects
        addr = state.allocate_heap_object(class_name)
        state.push(TaintValue.from_heap_ref(addr, state.heap))

    state.pc += 1
    return state


def transfer_dup(opcode: jvm.Dup, state: AbstractState) -> AbstractState:
    """
    Handle dup instruction.

    Duplicate top of stack.
    """
    value = state.peek()
    log.debug(f"  DUP {value}")
    state.push(value)
    state.pc += 1
    return state


def transfer_invoke_virtual(opcode: jvm.InvokeVirtual, state: AbstractState) -> AbstractState:
    """
    Handle invokevirtual instruction.

    This is the KEY operation - all string operations compile to invokevirtual.
    """
    method = opcode.method
    method_str = str(method)
    method_name = method.extension.name
    param_count = len(method.extension.params)

    log.debug(f"  INVOKE_VIRTUAL {method_name}")

    # Pop arguments (in reverse order)
    args = [state.pop() for _ in range(param_count)]
    args.reverse()

    # Pop object reference (for instance methods)
    obj_ref = state.pop()

    # Handle different method types

    # StringBuilder.append(String) - TAJ-style string carrier approach
    if "StringBuilder.append" in method_str or "StringBuffer.append" in method_str:
        if obj_ref.is_string_carrier:
            # TAJ-style: Accumulate taint directly in carrier
            if args:
                obj_ref.accumulate_taint(args[0].tainted_value)
                log.debug(f"    → String carrier append: {args[0]} → {obj_ref.carrier_taint}")
            # Push carrier back for chaining
            state.push(obj_ref)
        elif obj_ref.heap_ref is not None:
            # Fallback: Old heap-based approach (for compatibility)
            heap_obj = state.heap[obj_ref.heap_ref]
            if args:
                heap_obj.append(args[0].tainted_value)
                log.debug(f"    → Heap-based append: {args[0]}")
            state.push(obj_ref)
        else:
            log.warning(f"    → StringBuilder.append on unknown object!")
            state.push(TaintValue.untrusted("unknown"))

    # StringBuilder.toString() - TAJ-style string carrier approach
    elif MethodMatcher.is_string_builder_tostring(method):
        if obj_ref.is_string_carrier:
            # TAJ-style: Return accumulated carrier_taint
            result_taint = obj_ref.carrier_taint if obj_ref.carrier_taint else obj_ref.tainted_value
            result = TaintValue.from_tainted(result_taint)
            log.debug(f"    → String carrier toString() returns {result}")
            state.push(result)
        elif obj_ref.heap_ref is not None:
            # Fallback: Old heap-based approach (for compatibility)
            heap_obj = state.heap[obj_ref.heap_ref]
            result = TaintValue.from_tainted(heap_obj.to_string())
            log.debug(f"    → Heap-based toString() returns {result}")
            state.push(result)
        else:
            state.push(TaintValue.untrusted("unknown"))

    # String.concat, String.trim, String.replaceAll, etc. (taint-preserving)
    elif MethodMatcher.is_taint_preserving(method):
        # If ANY argument or object is tainted, result is tainted
        all_values = [obj_ref] + args
        if any(v.is_tainted for v in all_values):
            combined = TaintTransfer.concat(*[v.tainted_value for v in all_values])
            result = TaintValue.from_tainted(combined)
            log.debug(f"    → Taint-preserving operation returns {result}")
            state.push(result)
        else:
            state.push(TaintValue.trusted("result"))

    # Source methods (getParameter, readLine, etc.)
    elif MethodMatcher.is_source(method):
        source_type = detector.get_source_type(method_str)
        result = TaintValue.untrusted("user_input", source=source_type)
        log.debug(f"    → SOURCE method returns UNTRUSTED ({source_type})")
        state.push(result)

    # Sink methods (Statement.execute, etc.)
    elif MethodMatcher.is_sink(method):
        # Check if ANY argument is tainted
        if any(arg.is_tainted for arg in args):
            log.warning(f"    → SQL SINK called with TAINTED data!")
            log.warning(f"       VULNERABILITY DETECTED: {method_name}")
            state.vulnerability_detected = True
        state.push(TaintValue.trusted("void"))  # Most sinks return void

    # Unknown method - conservative: preserve taint
    else:
        log.debug(f"    → Unknown method, preserving taint conservatively")
        all_values = [obj_ref] + args
        if any(v.is_tainted for v in all_values):
            state.push(TaintValue.untrusted("unknown"))
        else:
            state.push(TaintValue.trusted("unknown"))

    state.pc += 1
    return state


def transfer_invoke_static(opcode: jvm.InvokeStatic, state: AbstractState) -> AbstractState:
    """
    Handle invokestatic instruction.

    Similar to invokevirtual but no object reference.
    """
    method = opcode.method
    method_str = str(method)
    method_name = method.extension.name
    param_count = len(method.extension.params)

    log.debug(f"  INVOKE_STATIC {method_name}")

    # Pop arguments
    args = [state.pop() for _ in range(param_count)]
    args.reverse()

    # Check if it's a sink (fully qualified JDBC methods only)
    if MethodMatcher.is_sink(method):
        # Check if ANY argument is tainted
        if any(arg.is_tainted for arg in args):
            log.warning(f"    → SQL SINK called with TAINTED data!")
            log.warning(f"       VULNERABILITY DETECTED: {method_name}")
            state.vulnerability_detected = True
        else:
            log.debug(f"    → SQL sink with safe data")
        state.push(TaintValue.trusted("void"))

    # Check if it's a source (fully qualified signatures only)
    elif MethodMatcher.is_source(method):
        source_type = detector.get_source_type(method_str)
        result = TaintValue.untrusted("user_input", source=source_type)
        log.debug(f"    → SOURCE method returns UNTRUSTED ({source_type})")
        state.push(result)

    # Unknown static method - conservative: preserve taint
    else:
        log.debug(f"    → Unknown static method, preserving taint conservatively")
        if any(arg.is_tainted for arg in args):
            state.push(TaintValue.untrusted("unknown"))
        else:
            state.push(TaintValue.trusted("unknown"))

    state.pc += 1
    return state


def transfer_invoke_special(opcode: jvm.InvokeSpecial, state: AbstractState) -> AbstractState:
    """
    Handle invokespecial instruction (constructor calls).

    Usually for calling <init> after NEW.
    """
    method = opcode.method
    param_count = len(method.extension.params)

    log.debug(f"  INVOKE_SPECIAL {method.extension.name}")

    # Pop arguments
    args = [state.pop() for _ in range(param_count)]

    # Pop object reference
    obj_ref = state.pop()

    # For constructors, just push the object reference back
    state.push(obj_ref)
    state.pc += 1
    return state


def transfer_invoke_interface(opcode: jvm.InvokeInterface, state: AbstractState) -> AbstractState:
    """
    Handle invokeinterface instruction.

    Used when calling methods on interfaces (e.g., java.sql.Statement).
    Similar to invokevirtual but for interface types.
    """
    method = opcode.method
    method_str = str(method)
    method_name = method.extension.name
    param_count = len(method.extension.params)

    log.debug(f"  INVOKE_INTERFACE {method_name}")

    # Pop arguments (in reverse order)
    args = [state.pop() for _ in range(param_count)]
    args.reverse()

    # Pop object reference (for instance methods)
    obj_ref = state.pop()

    # Check if it's a sink (e.g., Statement.executeQuery)
    if MethodMatcher.is_sink(method):
        # Check if ANY argument is tainted
        if any(arg.is_tainted for arg in args):
            log.warning(f"    → SQL SINK called with TAINTED data!")
            log.warning(f"       VULNERABILITY DETECTED: {method_name}")
            state.vulnerability_detected = True
        else:
            log.debug(f"    → SQL sink with safe data")
        state.push(TaintValue.trusted("result"))

    # Source methods
    elif MethodMatcher.is_source(method):
        source_type = detector.get_source_type(method_str)
        result = TaintValue.untrusted("user_input", source=source_type)
        log.debug(f"    → SOURCE method returns UNTRUSTED ({source_type})")
        state.push(result)

    # Taint-preserving operations
    elif MethodMatcher.is_taint_preserving(method):
        all_values = [obj_ref] + args
        if any(v.is_tainted for v in all_values):
            combined = TaintTransfer.concat(*[v.tainted_value for v in all_values])
            result = TaintValue.from_tainted(combined)
            state.push(result)
        else:
            state.push(TaintValue.trusted("result"))

    # Unknown method - conservative: preserve taint
    else:
        log.debug(f"    → Unknown interface method, preserving taint conservatively")
        all_values = [obj_ref] + args
        if any(v.is_tainted for v in all_values):
            state.push(TaintValue.untrusted("unknown"))
        else:
            state.push(TaintValue.trusted("unknown"))

    state.pc += 1
    return state


def transfer_invoke_dynamic(opcode: jvm.InvokeDynamic, state: AbstractState) -> AbstractState:
    """
    Handle invokedynamic instruction.

    In modern Java, this is often used for string concatenation via StringConcatFactory.
    For taint analysis, we treat it conservatively: if ANY argument is tainted, result is tainted.
    """
    method = opcode.method
    param_count = len(method.extension.params)

    log.debug(f"  INVOKE_DYNAMIC {method.extension.name} (likely string concat)")

    # Pop arguments
    args = [state.pop() for _ in range(param_count)]

    # If any argument is tainted, result is tainted (conservative)
    if any(arg.is_tainted for arg in args):
        combined = TaintTransfer.concat(*[arg.tainted_value for arg in args])
        result = TaintValue.from_tainted(combined)
        log.debug(f"    → Dynamic call with tainted args returns {result}")
        state.push(result)
    else:
        state.push(TaintValue.trusted("result"))

    state.pc += 1
    return state


def transfer_pop(opcode, state: AbstractState) -> AbstractState:
    """
    Handle pop instruction.

    Pop value from stack and discard it.
    """
    value = state.pop()
    log.debug(f"  POP {value}")
    state.pc += 1
    return state


def transfer_array_load(opcode: jvm.ArrayLoad, state: AbstractState) -> AbstractState:
    """
    Handle array load instruction (aaload, iaload, etc.).

    Sound array abstraction: if the array is tainted, loaded element is tainted.
    This is a conservative over-approximation (treats all elements as having same taint).
    """
    # Pop index and array reference
    index = state.pop()
    array_ref = state.pop()

    log.debug(f"  ARRAY_LOAD from {array_ref}[{index}]")

    # If array is tainted, loaded element is tainted
    if array_ref.is_tainted:
        result = TaintValue.untrusted("array_element", source="array_load")
        log.debug(f"    → Loaded TAINTED element from tainted array")
    else:
        result = TaintValue.trusted("array_element", source="array_load")
        log.debug(f"    → Loaded TRUSTED element from trusted array")

    state.push(result)
    state.pc += 1
    return state


def transfer_array_store(opcode: jvm.ArrayStore, state: AbstractState) -> AbstractState:
    """
    Handle array store instruction (aastore, iastore, etc.).

    Sound array abstraction: if stored value is tainted, array becomes tainted.
    Note: This is a simplification - proper analysis would track array elements separately.
    """
    # Pop value, index, and array reference
    value = state.pop()
    index = state.pop()
    array_ref = state.pop()

    log.debug(f"  ARRAY_STORE {value} into {array_ref}[{index}]")

    # If value is tainted, we should mark the array as tainted
    # For now, we don't track arrays in heap, so this is a no-op
    # The array's taint status is preserved in its reference

    state.pc += 1
    return state


def transfer_array_length(opcode: jvm.ArrayLength, state: AbstractState) -> AbstractState:
    """
    Handle arraylength instruction.

    Array length is always an integer, never tainted (it's metadata, not data).
    """
    array_ref = state.pop()
    log.debug(f"  ARRAY_LENGTH of {array_ref}")

    # Array length is never tainted (it's an integer derived from array structure)
    state.push(TaintValue.trusted(0, source="array_length"))
    state.pc += 1
    return state


def transfer_return(opcode: jvm.Return, state: AbstractState) -> Optional[AbstractState]:
    """
    Handle return instruction.

    Returns None to signal end of analysis.
    """
    log.debug("  RETURN")
    return None


# ============================================================================
# Main Analysis
# ============================================================================

def transfer_block(block: BasicBlock, state: AbstractState) -> AbstractState:
    """
    Apply transfer functions for all instructions in a basic block.

    Args:
        block: The basic block to analyze
        state: The abstract state at block entry

    Returns:
        The abstract state at block exit
    """
    current_state = state.copy()

    for opcode in block.instructions:
        log.debug(f"  [{opcode.offset:3d}] {opcode}")

        try:
            match opcode:
                case jvm.Push():
                    current_state = transfer_push(opcode, current_state)
                case jvm.Load():
                    current_state = transfer_load(opcode, current_state)
                case jvm.Store():
                    current_state = transfer_store(opcode, current_state)
                case jvm.New():
                    current_state = transfer_new(opcode, current_state)
                case jvm.Dup():
                    current_state = transfer_dup(opcode, current_state)
                case jvm.Pop():
                    current_state = transfer_pop(opcode, current_state)
                case jvm.ArrayLoad():
                    current_state = transfer_array_load(opcode, current_state)
                case jvm.ArrayStore():
                    current_state = transfer_array_store(opcode, current_state)
                case jvm.ArrayLength():
                    current_state = transfer_array_length(opcode, current_state)
                case jvm.InvokeVirtual():
                    current_state = transfer_invoke_virtual(opcode, current_state)
                case jvm.InvokeStatic():
                    current_state = transfer_invoke_static(opcode, current_state)
                case jvm.InvokeSpecial():
                    current_state = transfer_invoke_special(opcode, current_state)
                case jvm.InvokeDynamic():
                    current_state = transfer_invoke_dynamic(opcode, current_state)
                case jvm.InvokeInterface():
                    current_state = transfer_invoke_interface(opcode, current_state)
                case jvm.Return():
                    # Return doesn't change taint state, just signals end
                    pass
                case jvm.Goto():
                    # Goto doesn't change state, CFG handles control flow
                    pass
                case jvm.If() | jvm.Ifz():
                    # Conditional branches: pop comparison values, CFG handles flow
                    # For If: pops two values
                    # For Ifz: pops one value
                    if isinstance(opcode, jvm.If):
                        if len(current_state.stack) >= 2:
                            current_state.pop()
                            current_state.pop()
                    else:  # Ifz
                        if len(current_state.stack) >= 1:
                            current_state.pop()
                case _:
                    # Unknown opcode - skip conservatively
                    opcode_str = str(opcode)
                    if 'pop' in opcode_str.lower():
                        current_state = transfer_pop(opcode, current_state)
                    else:
                        log.debug(f"    → Unhandled opcode type: {type(opcode).__name__}")

        except Exception as e:
            log.error(f"Error processing opcode {opcode}: {e}")

    return current_state


def analyze_method(methodid: jvm.AbsMethodID) -> bool:
    """
    Analyze method using CFG-based worklist algorithm.

    This implements a proper forward data-flow analysis:
    1. Build CFG from bytecode
    2. Initialize entry block with initial state
    3. Use worklist to propagate taint until fixed point
    4. Report vulnerability if tainted data reaches sink

    Returns True if SQL injection vulnerability detected, False otherwise.
    """
    log.debug(f"\n{'='*60}")
    log.debug(f"Analyzing: {methodid}")
    log.debug(f"{'='*60}\n")

    # Get bytecode
    suite = Suite()
    opcodes = list(suite.method_opcodes(methodid))

    if not opcodes:
        return False

    log.debug(f"Method has {len(opcodes)} opcodes\n")

    # Build CFG
    cfg = build_cfg(opcodes)

    if not cfg:
        # Fallback to sequential analysis if CFG building fails
        log.warning("CFG building failed, falling back to sequential analysis")
        return analyze_method_sequential(methodid, opcodes)

    # Find entry block (offset 0 or first block)
    entry_offset = min(cfg.keys())

    # Initialize abstract states for each block
    # IN[b] = state at entry to block b
    # OUT[b] = state at exit from block b
    IN: Dict[int, Optional[AbstractState]] = {offset: None for offset in cfg}
    OUT: Dict[int, Optional[AbstractState]] = {offset: None for offset in cfg}

    # Initialize entry block with initial state (all params UNTRUSTED)
    initial_state = AbstractState.initial(methodid)
    IN[entry_offset] = initial_state

    # Worklist algorithm
    worklist = [entry_offset]
    iterations = 0
    max_iterations = 1000
    vulnerability_detected = False

    log.debug(f"Starting worklist analysis with {len(cfg)} blocks")

    while worklist and iterations < max_iterations:
        iterations += 1
        block_offset = worklist.pop(0)
        block = cfg[block_offset]

        log.debug(f"\nProcessing block {block_offset} (iteration {iterations})")

        # Compute IN[block] = join of all predecessor OUT states
        if block.predecessors:
            pred_states = [OUT[p] for p in block.predecessors if OUT[p] is not None]
            if pred_states:
                if len(pred_states) == 1:
                    IN[block_offset] = pred_states[0].copy()
                else:
                    # Join all predecessor states
                    joined = pred_states[0].copy()
                    for ps in pred_states[1:]:
                        joined = AbstractState.join(joined, ps)
                    IN[block_offset] = joined

        # If no input state yet, skip (will be processed when predecessor is done)
        if IN[block_offset] is None:
            continue

        # Apply transfer functions for the block
        old_out = OUT[block_offset]
        new_out = transfer_block(block, IN[block_offset])
        OUT[block_offset] = new_out

        # Check if vulnerability detected in this block
        if new_out.vulnerability_detected:
            vulnerability_detected = True
            log.debug(f"  Vulnerability detected in block {block_offset}!")

        # If OUT changed, add successors to worklist
        if old_out is None or old_out != new_out:
            for succ in block.successors:
                if succ not in worklist:
                    worklist.append(succ)
                    log.debug(f"  Added successor {succ} to worklist")

    log.debug(f"\nAnalysis completed in {iterations} iterations")
    log.debug(f"Vulnerability detected: {vulnerability_detected}")

    return vulnerability_detected


def analyze_method_sequential(methodid: jvm.AbsMethodID, opcodes: List[jvm.Opcode]) -> bool:
    """
    Fallback sequential analysis (original implementation).

    Used when CFG building fails or for simple straight-line code.
    """
    state = AbstractState.initial(methodid)

    for opcode in opcodes:
        log.debug(f"[{opcode.offset:3d}] {opcode}")

        try:
            match opcode:
                case jvm.Push():
                    state = transfer_push(opcode, state)
                case jvm.Load():
                    state = transfer_load(opcode, state)
                case jvm.Store():
                    state = transfer_store(opcode, state)
                case jvm.New():
                    state = transfer_new(opcode, state)
                case jvm.Dup():
                    state = transfer_dup(opcode, state)
                case jvm.Pop():
                    state = transfer_pop(opcode, state)
                case jvm.ArrayLoad():
                    state = transfer_array_load(opcode, state)
                case jvm.ArrayStore():
                    state = transfer_array_store(opcode, state)
                case jvm.ArrayLength():
                    state = transfer_array_length(opcode, state)
                case jvm.InvokeVirtual():
                    state = transfer_invoke_virtual(opcode, state)
                case jvm.InvokeStatic():
                    state = transfer_invoke_static(opcode, state)
                case jvm.InvokeSpecial():
                    state = transfer_invoke_special(opcode, state)
                case jvm.InvokeDynamic():
                    state = transfer_invoke_dynamic(opcode, state)
                case jvm.InvokeInterface():
                    state = transfer_invoke_interface(opcode, state)
                case jvm.Return():
                    break
                case _:
                    pass

        except Exception as e:
            log.error(f"Error processing opcode {opcode}: {e}")

    return getattr(state, 'vulnerability_detected', False)


def main():
    """Main entry point"""
    # Handle info command
    if len(sys.argv) == 2 and sys.argv[1] == "info":
        print("Bytecode Taint Analyzer")
        print("1.0")
        print("DTU Compute - Group 4")
        print("bytecode,taint,sqli")
        print("no")
        sys.exit(0)

    # Get method signature from command line
    if len(sys.argv) < 2:
        print("Usage: bytecode_taint_analyzer.py <method_signature>", file=sys.stderr)
        print("Example: bytecode_taint_analyzer.py jpamb.sqli.SQLi_DirectConcat.vulnerable", file=sys.stderr)
        sys.exit(1)

    method_signature = sys.argv[1]

    # Create suite
    suite = Suite()

    # Resolve method signature to method ID
    methodid = resolve_method_id(method_signature, suite)

    if methodid is None:
        print(f"error;0%")
        sys.exit(1)

    # Analyze the method
    has_vulnerability = analyze_method(methodid)

    # Output result in JPAMB format
    if has_vulnerability:
        print("sql injection;90%")
    else:
        print("ok;90%")

    sys.exit(0)


if __name__ == "__main__":
    main()
