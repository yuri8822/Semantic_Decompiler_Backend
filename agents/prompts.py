"""
System prompts and prompt builders for the three LLM specialists:

  Analyzer            understands one function; produces a semantic
                      annotation (names, types, fields, evidence, confidence).
                      Never writes code.
  Type Reconstructor  merges evidence from every function touching one
                      object type into a class layout.
  Code Reconstructor  writes one function's readable C++ from the improved
                      decompilation plus everything the knowledge base knows,
                      and fixes it when the Validator objects.

Ghidra stays the source of truth for behaviour throughout: every prompt
labels which facts are machine-proven and which are earlier LLM guesses.
"""

from knowledge.naming import sanitize_class_name

CONFIDENCE_GUIDE = """CONFIDENCE is your calibrated probability that a claim is correct:
  0.90-1.00  direct, unambiguous evidence (a symbol name, a string naming the value,
             an access pattern that admits one reading)
  0.60-0.89  strong but inferential (usage pattern, neighbour semantics)
  below 0.60 a guess
Wrong high-confidence claims are applied automatically and poison everything downstream.
Low-confidence claims are simply re-examined later. When unsure, give a LOW number."""

# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

ANALYZER_SYSTEM = """You are the ANALYZER in a reverse-engineering pipeline that rebuilds C++ source from a binary.
Ghidra is the source of truth for machine-level behaviour. Your job is semantic understanding of ONE function:
what it does, what its parameters, locals and return value mean, which class it belongs to, and what the
object fields it touches are. DO NOT write C++ code.

Rules:
- Every claim must be grounded in the input. Put the concrete facts you relied on in "evidence"
  (e.g. "writes param_1+0x18 with param_1[0x18]-param_2", "references string \\"Health\\"",
  "called by Enemy::Attack", "first argument used as object pointer").
- If GHIDRA NAME says "name from program symbols — KEEP IT", reuse that exact qualified name for "name"
  (set name_confidence 0.95+) and focus on parameters, locals, fields and return semantics.
- Names are C++ identifiers. Methods are written "Class::Method"; constructors "Class::Class";
  destructors "Class::~Class".
- A function is a method when its first parameter is used as an object pointer: offset accesses on it,
  passed as the first argument to methods of one class, or Ghidra already types it as "Class * this".
  Give that parameter role "this".
- Functions returning std::string (names ending in [abi:cxx11] or _abi_cxx11_, or building a string
  into the first pointer argument and returning it) take a hidden return slot: give that parameter
  role "return_slot" and set return_type "std::string".
- If RETURN VALUE USE BY CALLERS shows callers using the result, the function returns a value of the type
  they receive it as, even when its body seems not to produce one (e.g. it falls off the end of a non-void
  function, which compilers turn into a trap). Never answer "void" for such a function.
- Only report fields at offsets listed under OBSERVED MEMORY ACCESSES. "param" is the parameter index
  the offset is relative to; "class_name" is the type that parameter points to. Lines like
  "Piece * (via pPVar1) +0x14" are accesses through a pointer Ghidra knows the class of: report those
  with "param": -1 and that class as "class_name" — they reveal fields of other classes.
- Use C++ types: int, unsigned int, int64_t, uint64_t, bool, char, char *, const char *, float, double,
  void *, std::string, ClassName *. Prefer a known class name over void * when the evidence supports it.
- Locals: only rename variables listed under LOCAL VARIABLES, using their exact current name as old_name.
- Globals: only those listed under GLOBALS with an address.

""" + CONFIDENCE_GUIDE + """

Return ONLY one JSON object, no prose, in exactly this shape:
{
  "name": "Player::TakeDamage",
  "name_confidence": 0.9,
  "class_name": "Player",
  "method_kind": "method | constructor | destructor | static | virtual | free",
  "summary": "One sentence describing what the function does.",
  "evidence": ["fact 1", "fact 2"],
  "return_type": "void",
  "return_meaning": "what the return value means, or empty",
  "return_confidence": 0.8,
  "params": [
    {"index": 0, "old_name": "param_1", "name": "this", "type": "Player *", "role": "this",
     "meaning": "the player being damaged", "confidence": 0.95},
    {"index": 1, "old_name": "param_2", "name": "amount", "type": "int", "role": "normal",
     "meaning": "damage to subtract", "confidence": 0.85}
  ],
  "locals": [{"old_name": "iVar1", "name": "remainingHealth", "type": "int", "confidence": 0.7}],
  "fields": [{"param": 0, "class_name": "Player", "offset": "0x18", "name": "health", "type": "int",
              "confidence": 0.9, "evidence": "decremented by amount, clamped at 0"}],
  "globals": [{"address": "0x405000", "old_name": "DAT_00405000", "name": "g_player", "type": "Player *",
               "confidence": 0.7}],
  "notes": ["relationships with callers/callees worth recording"]
}
Include every parameter Ghidra lists (by index). Use empty lists when there is nothing to report."""


def build_analyzer_prompt(ctx, fn, rec, round_num: int) -> str:
    parts = [
        f"ANALYSIS ROUND {round_num}",
        ctx.header(fn),
        "\nPARAMETERS (Ghidra):", ctx.parameters(fn),
        "\nLOCAL VARIABLES (Ghidra):", ctx.locals(fn),
        "\nOBSERVED MEMORY ACCESSES (proven from p-code: parameter + constant offset):", ctx.field_accesses(fn),
        "\nPARAMETER POINTERS PASSED TO CALLS:", ctx.arg_passes(fn),
        "\nCALLEES:", ctx.callees(fn),
        "\nCALLERS:", ctx.callers(fn),
        "\nRETURN VALUE USE BY CALLERS (Ghidra's own call sites):", ctx.return_uses(fn),
        "\nGLOBALS:", ctx.globals(fn),
        "\nREFERENCED STRINGS:", ctx.strings(fn),
    ]
    this_class = _this_class(fn, rec)
    if this_class:
        parts += ["\nCURRENT KNOWLEDGE OF THIS FUNCTION'S CLASS:", ctx.class_layout(this_class)]
    parts += ["\nKNOWN CLASSES IN THIS PROGRAM:", ctx.known_classes_brief()]
    if rec.analysis and round_num > 1:
        a = rec.analysis
        parts += [
            "\nYOUR PREVIOUS ANALYSIS (round {}) — revisit it; the decompilation below now reflects the "
            "names and types applied since:".format(a.round),
            f"  name {a.name} (confidence {a.name_confidence:.2f}); summary: {a.summary}",
        ]
        low = [f"param {p.index} {p.name} ({p.confidence:.2f})" for p in a.params if p.confidence < 0.6]
        if low:
            parts.append("  low-confidence: " + ", ".join(low))
        if a.contradictions:
            parts.append("  CONTRADICTED BY THE BINARY — resolve this:")
            parts += [f"    - {c}" for c in a.contradictions]
    parts += [
        "\nGHIDRA DECOMPILATION:", ctx.decompiled(fn),
        "\nASSEMBLY:", ctx.assembly(fn),
        "\nReturn the JSON analysis now.",
    ]
    return "\n".join(parts)


def _this_class(fn, rec) -> str:
    if rec.analysis and rec.analysis.is_method:
        return rec.analysis.class_name
    if fn.namespace_is_class:
        return fn.namespace
    return ""


# ---------------------------------------------------------------------------
# Type Reconstructor
# ---------------------------------------------------------------------------

TYPE_SYSTEM = """You are the TYPE RECONSTRUCTOR in a reverse-engineering pipeline that rebuilds C++ source from a binary.
You receive every piece of evidence about ONE object type: the functions that operate on it, the memory
offsets each of them provably reads/writes through the object pointer (from Ghidra p-code, ground truth),
the field names/types the analyzer guessed per function, and calls that pass the object pointer on.

Determine whether these functions really operate on the same object type, and reconstruct its C++ layout.

Rules:
- Only place fields at offsets that appear in the observed accesses or the analyzer guesses.
  Field size must match the observed access size (a 4-byte access is int/unsigned int/float, an 8-byte
  access on a 64-bit target is a pointer, int64_t or double, 1 byte is bool/char, 32 bytes at one offset
  passed to std::string methods is a std::string).
- Fields must not overlap. Reconcile conflicting guesses from different functions and say why in notes.
- A pointer to this object passed with an offset (this+0x20) to another class's method means an embedded
  member object of that class at that offset.
- If an offset-0 pointer-sized field is written with a constant address in constructors, it is the vtable
  pointer: name it "vftable", type "void **".
- size: the full object size if a constructor/allocation shows it (e.g. operator_new(0x28) followed by the
  constructor), otherwise the end of the last field. Give size_confidence accordingly.
- base_class: only if a constructor calls another class's constructor on the same pointer at offset 0.
- same_as: other listed class names that are provably the same type (identical access patterns AND
  shared functions), else empty.

""" + CONFIDENCE_GUIDE + """

Return ONLY one JSON object, no prose:
{
  "name": "Player",
  "kind": "class",
  "size": "0x24",
  "size_confidence": 0.6,
  "base_class": "",
  "base_confidence": 0.0,
  "same_as": [],
  "confidence": 0.85,
  "fields": [
    {"offset": "0x18", "size": 4, "name": "health", "type": "int", "confidence": 0.95,
     "evidence": "read by IsDead, decremented by TakeDamage"}
  ],
  "notes": "short reasoning"
}"""


def build_type_prompt(ctx, class_name: str, evidence: dict) -> str:
    parts = [
        f"CANDIDATE TYPE: {class_name}",
        f"TARGET: {ctx.ir.program.language}, pointer size {ctx.ir.program.pointer_size} bytes",
        "\nCURRENT LAYOUT (from earlier reconstruction, may be empty):", ctx.class_layout(class_name),
        "\nFUNCTIONS OPERATING ON IT:",
    ]
    for item in evidence["functions"]:
        parts.append(f"\n- {item['address']} {item['name']} [{item['role']}] — {item['summary']}")
        parts.append("  observed accesses through the object pointer:")
        parts.append(item["accesses"] or "    (none)")
        if item["passes"]:
            parts.append("  object pointer passed on:")
            parts.append(item["passes"])
        if item["guesses"]:
            parts.append("  analyzer field guesses:")
            parts.append(item["guesses"])
        if item.get("decompiled"):
            parts.append("  decompilation (excerpt):")
            parts.append(item["decompiled"])
    if evidence.get("ghidra_struct"):
        parts += ["\nSTRUCTURE GHIDRA CURRENTLY HAS:", evidence["ghidra_struct"]]
    parts += [
        "\nOTHER KNOWN CLASSES:", ctx.known_classes_brief(),
        "\nReturn the JSON layout now.",
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Code Reconstructor
# ---------------------------------------------------------------------------

# Concrete decompiler-artifact -> idiomatic-C++ pairs, taken from what Ghidra
# actually prints for MinGW g++ binaries (the Chess.exe export).
ARTIFACT_TRANSLATIONS = """COMMON DECOMPILER ARTIFACTS AND WHAT TO WRITE INSTEAD
Left side: what Ghidra prints. Right side: what to write. Only apply a rule when the code really matches it.

MEMORY
- operator_new(0x18) / operator.new(0x18)  ->  new T   (when 0x18 is sizeof(T))
- operator_new__(0x40) holding 8 pointers  ->  new T*[8]
- operator_delete(p) or operator_delete(p, 0x18)  ->  delete p;   operator_delete__(p)  ->  delete[] p
- p = (Foo *)operator_new(0x18);  Foo::Foo(p);  ->  Foo *p = new Foo();

LOCAL OBJECTS
- Foo local_a8 [152];  Foo::Foo(local_a8);  ...  Foo::~Foo(local_a8);  ->  Foo foo;
- string local_818 [32];  ->  std::string text;   (a 32-byte buffer is a std::string)
- std::string::string(&s, "text", &alloc);  ->  std::string s = "text";
- Foo::~Foo(&x); or std::string::~string(&s); at the end of a scope  ->  remove it
- allocator local_21; ... ~__new_allocator();  ->  remove them

CLASSES AND METHODS
- void __thiscall Foo::Bar(Foo *this, int a)  ->  void Foo::Bar(int a)
- Base::Base((Base *)this); as the first line of a constructor  ->  Foo::Foo() : Base()
- *(undefined ***)this = &PTR_Something_140009a60;  ->  remove it   (the compiler sets the vtable)
- std::string::string((string *)(this + 0x38)); in a constructor / ~string in a destructor  ->  remove it
- *(int *)(this + 8)  ->  this->fieldName   (use the field the CLASS LAYOUT declares at that offset)
- Foo::Bar(obj, a)  ->  obj->Bar(a);   Bar(this) inside another method  ->  Bar()

VIRTUAL CALLS
- (**(code **)(*(longlong *)obj + 0x18))(obj, a)  ->  obj->Method(a)   (slot = offset / pointer size)

INPUT AND OUTPUT
- _ZSt4cout / _ZSt3cin / _ZSt4endl  ->  std::cout / std::cin / std::endl
- std::operator<<((ostream *)&_ZSt4cout, "text")  ->  std::cout << "text"   (join chains into one statement)
- std::istream::operator>>((istream *)&_ZSt3cin, (int *)(this + 8))  ->  std::cin >> this->x
- std::getline<...>((istream *)&_ZSt3cin, (string *)(this + 0x38))  ->  std::getline(std::cin, this->name)

POINTERS, TYPES, EXPRESSIONS
- *(T *)(base + (longlong)i * 8)  ->  base[i];   (void *)0x0 as a pointer  ->  nullptr
- undefined8/4/2/1  ->  the real type from usage, else uint64_t/uint32_t/uint16_t/uint8_t
- longlong / ulonglong / uint  ->  long long / unsigned long long / unsigned int
- x = x + 1;  ->  ++x;     for (i = 0; i < n; i = i + 1)  ->  for (int i = 0; i < n; ++i)
- goto backwards  ->  a loop;  goto forwards  ->  if/else, break or continue
- a temporary assigned once and used once right after  ->  use the expression directly
- __main(); at the top of main  ->  remove it"""

CODE_SYSTEM = """You are the CODE RECONSTRUCTOR in a reverse-engineering pipeline that rebuilds C++ source from a binary.
Write the readable, idiomatic C++17 implementation of ONE function.

Ground rules:
- Ghidra's decompilation (and the assembly) is the ground truth for behaviour. Preserve every call, branch,
  loop, memory write, constant and return value. Do not invent logic, constants, error handling or calls.
- Implement EXACTLY the REQUIRED SIGNATURE: same qualified name, return type, parameter types and order.
  Class declarations, includes and other functions' prototypes already exist in the project header —
  do NOT write class/struct definitions, #includes, or other functions.
- Access object fields by the names in the CLASS LAYOUT. If the code touches an offset the layout does
  not declare, use an explicit cast on the raw offset and add a `// TODO: unknown field +0xNN` comment.
- Call program functions by the names given under CALLEES (they are declared with those signatures).
  Library/runtime callees become their standard C++ equivalents (operator_new -> new, std streams, ...).
- Items marked "medium confidence" are uncertain: keep them, but add a `// TODO:` comment saying so.
- Prefer clarity: meaningful local names, no redundant casts, structured control flow.

""" + ARTIFACT_TRANSLATIONS + """

Output ONLY the function definition inside a single ```cpp code block. No prose."""


def build_code_prompt(ctx, fn, sig, rec) -> str:
    parts = [
        "REQUIRED SIGNATURE:", "  " + sig.definition_head(),
        "\nWHAT THE ANALYZER CONCLUDED:", _analysis_summary(rec),
    ]
    if sig.todos:
        parts += ["\nUNCERTAIN (medium confidence — keep but mark // TODO):"] + [f"  {t}" for t in sig.todos]
    if sig.class_name:
        parts += ["\nCLASS LAYOUT:", ctx.class_layout(sig.class_name)]
    other = other_classes(ctx, fn, sig)
    if other:
        parts += ["\nOTHER CLASSES THIS FUNCTION TOUCHES:"] + [ctx.class_layout(c) for c in other]
    parts += [
        "\nOBSERVED MEMORY ACCESSES (ground truth):", ctx.field_accesses(fn),
        "\nCALLEES:", ctx.callees(fn),
        "\nCALLERS:", ctx.callers(fn),
        "\nGLOBALS:", _globals_for_code(ctx, fn),
        "\nREFERENCED STRINGS:", ctx.strings(fn),
        "\nGHIDRA DECOMPILATION (after applying recovered names and types):", ctx.decompiled(fn),
        "\nASSEMBLY:", ctx.assembly(fn),
        "\nWrite the function now.",
    ]
    return "\n".join(parts)


def build_fix_prompt(ctx, fn, sig, rec, code: str, issues: list, compiler_output: str = "") -> str:
    parts = [build_code_prompt(ctx, fn, sig, rec), "\n\nYOUR PREVIOUS ATTEMPT:", "```cpp", code, "```"]
    if issues:
        parts.append("\nTHE VALIDATOR FOUND THESE PROBLEMS (checked against the binary):")
        parts += [f"  - [{i.severity}] {i.message}" for i in issues]
    if compiler_output:
        parts += ["\nCOMPILER ERRORS (g++, compiled against the generated project header):", compiler_output]
    parts.append("\nFix these problems. Keep everything else unchanged. Return the full corrected function.")
    return "\n".join(parts)


def _analysis_summary(rec) -> str:
    a = rec.analysis
    if a is None:
        return "  (not analyzed)"
    lines = [f"  {a.summary}"]
    for p in a.params:
        if p.role == "normal" and p.meaning:
            lines.append(f"  param {p.name}: {p.meaning}")
    if a.return_meaning:
        lines.append(f"  returns: {a.return_meaning}")
    for e in a.evidence[:5]:
        lines.append(f"  evidence: {e}")
    return "\n".join(lines)


def other_classes(ctx, fn, sig) -> list:
    """Classes besides the function's own whose layout the code needs (also part of the code cache key)."""
    names = set()
    for a in fn.field_accesses:   # fields reached through typed pointers, e.g. a Piece * from the board
        cls = sanitize_class_name(a.type) if a.param < 0 and a.type else ""
        if cls in ctx.kb.types and cls != sig.class_name:
            names.add(cls)
    for p in sig.params:
        base = p.type.replace("const ", "").rstrip(" *&")
        if base in ctx.kb.types and base != sig.class_name:
            names.add(base)
    for c in fn.calls:
        s = ctx.signatures.get(c.address)
        if s and s.class_name and s.class_name != sig.class_name and s.class_name in ctx.kb.types:
            names.add(s.class_name)
    return sorted(names)[:6]


def _globals_for_code(ctx, fn) -> str:
    out = []
    for g in fn.globals[:30]:
        rec = ctx.kb.globals.get(g.address) if g.address else None
        if rec and rec.name:
            out.append(f"  {rec.name} : {rec.type or g.type}  (Ghidra: {g.name})")
        else:
            out.append(f"  {g.name} : {g.type or '?'}")
    return "\n".join(out) or "  (none)"
