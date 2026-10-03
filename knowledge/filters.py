"""
Scope filter: which functions are library/runtime code rather than
application logic. Excluded functions are never sent to an LLM; they stay
in the knowledge base so callers can still be told what they call.

Heuristic by design: false negatives (a library function that slips through)
are acceptable, false positives (dropping real application code) are not, so
every rule leans on names the C++ standard or the toolchain reserves.
"""

import re

from ghidra_io.ir import FunctionIR

# Namespaces that are always the implementation's, never the application's.
_LIBRARY_NAMESPACES = ("std", "__gnu_cxx", "__cxxabiv1", "__gnu_debug")

# _M_xxx / _S_xxx: reserved for the standard library implementation.
_STL_INTERNAL_NAME_RE = re.compile(r"^_[MS]_\w+$")
_STL_THROW_HELPER_RE = re.compile(r"^__throw_\w+$")
_STL_EXACT_NAMES = frozenset({
    "_Alloc_hider", "_Rep", "_Sp_counted_base", "_Guard", "new_allocator",
    "__new_allocator", "_Rep_base", "_Sp_counted_ptr", "getline",
})
_STL_CLASS_NAMES = frozenset({
    "string", "basic_string", "wstring", "vector", "map", "set", "unordered_map",
    "unordered_set", "allocator", "pair", "istream", "ostream", "iostream",
    "stringstream", "unique_ptr", "shared_ptr", "char_traits",
}) | _STL_EXACT_NAMES

# Operators the C++ runtime provides.
_RUNTIME_OPERATORS = frozenset({
    "operator.new", "operator.new[]", "operator.delete", "operator.delete[]",
    "operator_new", "operator_new__", "operator_delete", "operator_delete__",
})

_CRT_EXACT_NAMES = frozenset({
    "_start", "__tmainCRTStartup", "mainCRTStartup", "WinMainCRTStartup", "wmainCRTStartup",
    "wWinMainCRTStartup", "pre_c_init", "pre_cpp_init", "__getmainargs", "__wgetmainargs",
    "__main", "_initterm", "_initterm_e", "_cexit", "_exit", "_amsg_exit",
    "__do_global_ctors", "__do_global_dtors", "__gcc_register_frame", "__gcc_deregister_frame",
    "atexit", "_onexit", "_crt_atexit", "__dyn_tls_init", "__dyn_tls_dtor",
    "_pei386_runtime_relocator", "__mingw_TLScallback", "__mingwthr_run_key_dtors",
    "__tlregdtor", "_gnu_exception_handler", "_matherr", "__setusermatherr", "_fpreset",
    "__report_error", "_ValidateImageBase", "_FindPESection", "_FindPESectionByName",
    "_FindPESectionExec", "_GetPEImageBase", "_IsNonwritableInCurrentImage",
    "mark_section_writable", "___chkstk_ms", "__chkstk", "_alloca_probe", "__p__fmode",
    "__p__commode", "__p___initenv", "__acrt_iob_func", "__set_app_type", "_setargv",
    "mingw_set_invalid_parameter_handler", "mingw_get_invalid_parameter_handler",
    "__security_init_cookie", "__security_check_cookie", "__GSHandlerCheck",
    "_RTC_CheckStackVars", "_RTC_InitBase", "_RTC_Shutdown", "__scrt_common_main_seh",
    "__scrt_initialize_crt", "__scrt_uninitialize_crt", "_CRT_INIT", "DllMainCRTStartup",
})
_CRT_PATTERNS = (
    re.compile(r"^__mingw_"), re.compile(r"^___"), re.compile(r"^__do_global_"),
    re.compile(r"^__scrt_"), re.compile(r"^__acrt_"), re.compile(r"^__vcrt_"),
    re.compile(r"^_RTC_"), re.compile(r"^__security_"),
)

_JUMPTABLE_WARNINGS = ("Could not recover jumptable", "Treating indirect jump as call")


def _top_namespace(fn: FunctionIR) -> str:
    return fn.namespace.split("::", 1)[0] if fn.namespace else ""


def _base_name(name: str) -> str:
    idx = name.find("<")
    return name[:idx] if idx > 0 else name


def is_library_namespace(fn: FunctionIR) -> bool:
    top = _top_namespace(fn)
    # Ghidra sometimes drops the std:: prefix: 'char_traits<char>::eq'.
    return top in _LIBRARY_NAMESPACES or _base_name(top) in _STL_CLASS_NAMES


def is_stl_internal(fn: FunctionIR) -> bool:
    base = _base_name(fn.name)
    if base in _RUNTIME_OPERATORS:
        return True
    if _STL_INTERNAL_NAME_RE.match(base) or _STL_THROW_HELPER_RE.match(base):
        return True
    if base in _STL_EXACT_NAMES:
        return True
    if base.lstrip("~") in _STL_CLASS_NAMES and not fn.namespace_is_class:
        return True
    this = fn.param(0)
    if this is not None and this.is_this and this.type.rstrip(" *") in _STL_CLASS_NAMES:
        return True
    # Free std stream operators: operator<<(ostream*, char*) and friends.
    if base in ("operator<<", "operator>>"):
        types = {p.type.rstrip(" *") for p in fn.parameters}
        if types & {"ostream", "istream", "basic_ostream", "basic_istream"}:
            other = types - {"ostream", "istream", "basic_ostream", "basic_istream"}
            if not other or other <= {"string", "char", "int", "uint", "long", "longlong",
                                      "ulonglong", "short", "float", "double", "bool", "void"}:
                return True
    return False


def is_crt_internal(fn: FunctionIR) -> bool:
    return fn.name in _CRT_EXACT_NAMES or any(p.match(fn.name) for p in _CRT_PATTERNS)


def is_unresolved_self_reference(fn: FunctionIR) -> bool:
    """Ghidra's own artifact: an unresolvable call decompiled as a self-call."""
    return fn.address in fn.callees and any(w in fn.decompiled for w in _JUMPTABLE_WARNINGS)


def is_garbled_name(name: str) -> bool:
    """Ghidra truncated a deeply-qualified name to a fragment like 'string*)'."""
    return "(" in name or ")" in name


def exclusion_reason(fn: FunctionIR) -> str:
    """'' if the function is application code to reconstruct, else why not."""
    if is_garbled_name(fn.name):
        return "garbled/truncated symbol name (function-local class member)"
    if is_library_namespace(fn):
        return f"standard-library namespace ({_top_namespace(fn)}::)"
    if is_stl_internal(fn):
        return "STL/C++ runtime internal, provided by the standard library"
    if is_unresolved_self_reference(fn):
        return "unresolvable call target decompiled as a self-call, not real logic"
    if is_crt_internal(fn):
        return "C runtime startup/support code, provided by the toolchain"
    if not fn.decompiled.strip():
        return f"Ghidra could not decompile it ({fn.decompile_error or 'no output'})"
    return ""


_IMPORTED_DATA_RE = re.compile(r"^(_Z|\.refptr\.|__imp_|__fu\d*_|__iob)")


def is_imported_data(name: str) -> bool:
    """Data symbols that belong to linked libraries (std::cout, IAT slots...)."""
    return bool(_IMPORTED_DATA_RE.match(name))
