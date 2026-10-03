// Exports the current program as the pipeline's intermediate representation:
// one JSON document holding program metadata, every non-external function
// (decompilation, assembly, call graph by address, strings, globals, types,
// and p-code-derived memory accesses relative to each parameter), the
// program's defined strings, and the class structures Ghidra currently has.
//
// Ghidra is the source of truth for machine-level behaviour; everything the
// LLM agents later claim is checked against what this script records.
//
// Script args:  <output.json>
//
//@category SemanticDecompiler

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

import com.google.gson.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportProgram extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final int MAX_ASSEMBLY_LINES = 4000;
    private static final int MAX_PROGRAM_STRINGS = 20000;
    private static final int MAX_TRACE_DEPTH = 16;

    private DecompInterface decompiler;
    private Listing listing;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            throw new IllegalArgumentException("usage: ExportProgram.java <output.json>");
        }
        File outFile = new File(args[0]);
        outFile.getParentFile().mkdirs();

        listing = currentProgram.getListing();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decompiler = new DecompInterface();
        decompiler.setOptions(opts);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        JsonObject root = new JsonObject();
        root.add("program", exportProgramInfo());

        JsonArray functions = new JsonArray();
        int exported = 0, skipped = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function func = it.next();
            if (func.isExternal() || func.isThunk()) {
                continue;
            }
            try {
                functions.add(exportFunction(func));
                exported++;
            } catch (Throwable t) {
                // One pathological function (e.g. a decompile blowing the heap)
                // must not abort the export of the whole binary.
                println("WARNING: skipping " + func.getName() + ": " + t);
                skipped++;
                if (t instanceof OutOfMemoryError) {
                    System.gc();
                }
            }
        }
        root.add("functions", functions);
        root.add("strings", exportProgramStrings());
        root.add("classes", exportClasses());

        decompiler.dispose();

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8)) {
            gson.toJson(root, w);
        }

        println("=== ExportProgram complete ===");
        println("Functions exported : " + exported);
        println("Functions skipped  : " + skipped);
        println("Output             : " + outFile.getAbsolutePath());
    }

    // ---------------------------------------------------------------------
    // Program
    // ---------------------------------------------------------------------

    private JsonObject exportProgramInfo() {
        JsonObject o = new JsonObject();
        o.addProperty("name", currentProgram.getName());
        o.addProperty("path", String.valueOf(currentProgram.getExecutablePath()));
        o.addProperty("format", String.valueOf(currentProgram.getExecutableFormat()));
        o.addProperty("sha256", String.valueOf(currentProgram.getExecutableSHA256()));
        o.addProperty("language", currentProgram.getLanguageID().toString());
        o.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        o.addProperty("image_base", addr(currentProgram.getImageBase()));
        o.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
        return o;
    }

    // ---------------------------------------------------------------------
    // Function
    // ---------------------------------------------------------------------

    private JsonObject exportFunction(Function func) throws Exception {
        JsonObject o = new JsonObject();
        Namespace parent = func.getParentNamespace();
        boolean global = parent == null || parent.isGlobal();

        o.addProperty("address", addr(func.getEntryPoint()));
        o.addProperty("name", func.getName());
        o.addProperty("full_name", func.getName(true));
        o.addProperty("namespace", global ? "" : parent.getName(true));
        o.addProperty("namespace_is_class", !global && parent instanceof GhidraClass);
        o.addProperty("name_source", func.getSymbol().getSource().toString());
        o.addProperty("signature_source", func.getSignatureSource().toString());
        o.addProperty("calling_convention", String.valueOf(func.getCallingConventionName()));
        o.addProperty("comment", func.getComment() == null ? "" : func.getComment());
        o.addProperty("body_size", func.getBody().getNumAddresses());

        Set<String> types = new TreeSet<>();
        JsonObject stats = new JsonObject();

        DecompileResults dr = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);
        HighFunction high = (dr != null && dr.decompileCompleted()) ? dr.getHighFunction() : null;
        DecompiledFunction df = (dr != null && dr.decompileCompleted()) ? dr.getDecompiledFunction() : null;

        if (high != null && df != null) {
            o.addProperty("decompiled", df.getC());
            o.addProperty("signature", df.getSignature().trim());
            o.addProperty("decompile_error", "");
            DataType ret = high.getFunctionPrototype().getReturnType();
            o.addProperty("return_type", ret == null ? "void" : ret.getDisplayName());
            if (ret != null) types.add(ret.getDisplayName());
            exportHighVariables(high, o, types);
            exportPcodeFacts(high, o, stats);
        } else {
            o.addProperty("decompiled", "");
            o.addProperty("signature", func.getPrototypeString(false, false));
            o.addProperty("decompile_error", dr == null ? "no result" : String.valueOf(dr.getErrorMessage()));
            o.addProperty("return_type", func.getReturnType().getDisplayName());
            types.add(func.getReturnType().getDisplayName());
            JsonArray params = new JsonArray();
            for (Parameter p : func.getParameters()) {
                JsonObject po = new JsonObject();
                po.addProperty("index", p.getOrdinal());
                po.addProperty("name", p.getName());
                po.addProperty("type", p.getDataType().getDisplayName());
                po.addProperty("storage", p.getVariableStorage().toString());
                po.addProperty("is_this", Function.THIS_PARAM_NAME.equals(p.getName()));
                po.addProperty("hidden_return", false);
                params.add(po);
                types.add(p.getDataType().getDisplayName());
            }
            o.add("parameters", params);
            o.add("locals", new JsonArray());
            o.add("field_accesses", new JsonArray());
            o.add("arg_passes", new JsonArray());
        }

        o.add("assembly", exportAssembly(func, stats));
        stats.addProperty("basic_blocks", countBlocks(func));
        o.add("stats", stats);

        exportCallGraph(func, o);
        exportDataReferences(func, o);

        JsonArray typeArr = new JsonArray();
        for (String t : types) typeArr.add(t);
        o.add("types", typeArr);
        return o;
    }

    private void exportHighVariables(HighFunction high, JsonObject o, Set<String> types) {
        LocalSymbolMap lsm = high.getLocalSymbolMap();
        JsonArray params = new JsonArray();
        for (int i = 0; i < lsm.getNumParams(); i++) {
            HighSymbol s = lsm.getParamSymbol(i);
            if (s == null) continue;
            JsonObject po = new JsonObject();
            po.addProperty("index", i);
            po.addProperty("name", s.getName());
            po.addProperty("type", s.getDataType().getDisplayName());
            po.addProperty("storage", String.valueOf(s.getStorage()));
            po.addProperty("is_this", s.isThisPointer());
            po.addProperty("hidden_return", s.isHiddenReturn());
            params.add(po);
            types.add(s.getDataType().getDisplayName());
        }
        o.add("parameters", params);

        JsonArray locals = new JsonArray();
        Iterator<HighSymbol> syms = lsm.getSymbols();
        while (syms.hasNext()) {
            HighSymbol s = syms.next();
            if (s.isParameter()) continue;
            JsonObject lo = new JsonObject();
            lo.addProperty("name", s.getName());
            lo.addProperty("type", s.getDataType().getDisplayName());
            lo.addProperty("storage", String.valueOf(s.getStorage()));
            locals.add(lo);
            types.add(s.getDataType().getDisplayName());
        }
        o.add("locals", locals);
    }

    // ---------------------------------------------------------------------
    // P-code facts: memory accesses relative to parameters, and which
    // callees receive a (possibly offset) parameter pointer. These are the
    // ground-truth evidence the type reconstructor and validator rely on.
    // ---------------------------------------------------------------------

    private static final class ParamBase {
        final int slot;
        final String name;
        final long offset;

        ParamBase(int slot, String name, long offset) {
            this.slot = slot;
            this.name = name;
            this.offset = offset;
        }
    }

    private void exportPcodeFacts(HighFunction high, JsonObject o, JsonObject stats) {
        JsonArray accesses = new JsonArray();
        JsonArray passes = new JsonArray();
        int cbranch = 0, branchind = 0, calls = 0, callind = 0, loads = 0, stores = 0, returns = 0;

        Iterator<PcodeOpAST> ops = high.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opc = op.getOpcode();
            switch (opc) {
                case PcodeOp.CBRANCH: cbranch++; break;
                case PcodeOp.BRANCHIND: branchind++; break;
                case PcodeOp.RETURN: returns++; break;
                case PcodeOp.CALLIND: callind++; calls++; break;
                case PcodeOp.CALL: {
                    calls++;
                    Address target = op.getInput(0).getAddress();
                    for (int i = 1; i < op.getNumInputs(); i++) {
                        ParamBase b = traceToParam(op.getInput(i));
                        if (b == null) continue;
                        JsonObject p = new JsonObject();
                        p.addProperty("callee", addr(resolveThunk(target)));
                        p.addProperty("arg", i - 1);
                        p.addProperty("param", b.slot);
                        p.addProperty("param_name", b.name);
                        p.addProperty("offset", b.offset);
                        p.addProperty("at", addr(op.getSeqnum().getTarget()));
                        passes.add(p);
                    }
                    break;
                }
                case PcodeOp.LOAD:
                case PcodeOp.STORE: {
                    boolean isLoad = opc == PcodeOp.LOAD;
                    if (isLoad) loads++; else stores++;
                    ParamBase b = traceToParam(op.getInput(1));
                    if (b == null) break;
                    int size = isLoad ? op.getOutput().getSize() : op.getInput(2).getSize();
                    JsonObject a = new JsonObject();
                    a.addProperty("param", b.slot);
                    a.addProperty("param_name", b.name);
                    a.addProperty("offset", b.offset);
                    a.addProperty("size", size);
                    a.addProperty("access", isLoad ? "read" : "write");
                    a.addProperty("at", addr(op.getSeqnum().getTarget()));
                    accesses.add(a);
                    break;
                }
                default:
                    break;
            }
        }
        o.add("field_accesses", accesses);
        o.add("arg_passes", passes);
        stats.addProperty("cbranches", cbranch);
        stats.addProperty("switches", branchind);
        stats.addProperty("calls", calls);
        stats.addProperty("indirect_calls", callind);
        stats.addProperty("loads", loads);
        stats.addProperty("stores", stores);
        stats.addProperty("returns", returns);
    }

    /**
     * Walks a pointer varnode back through pure address arithmetic (copies,
     * casts, constant adds, PTRSUB/PTRADD with constant operands) to a
     * function parameter. Returns null when the pointer has any other origin
     * (a load, a phi node, a non-constant index...), so only offsets that are
     * provably "parameter + constant" are ever reported.
     */
    private ParamBase traceToParam(Varnode v) {
        long off = 0;
        for (int depth = 0; depth < MAX_TRACE_DEPTH && v != null; depth++) {
            HighVariable hv = v.getHigh();
            if (hv instanceof HighParam) {
                return new ParamBase(((HighParam) hv).getSlot(), hv.getName(), off);
            }
            PcodeOp def = v.getDef();
            if (def == null) return null;
            switch (def.getOpcode()) {
                case PcodeOp.COPY:
                case PcodeOp.CAST:
                    v = def.getInput(0);
                    break;
                case PcodeOp.PTRSUB:
                    if (!def.getInput(1).isConstant()) return null;
                    off += def.getInput(1).getOffset();
                    v = def.getInput(0);
                    break;
                case PcodeOp.PTRADD: {
                    Varnode idx = def.getInput(1), sz = def.getInput(2);
                    if (!idx.isConstant() || !sz.isConstant()) return null;
                    off += signed(idx) * sz.getOffset();
                    v = def.getInput(0);
                    break;
                }
                case PcodeOp.INT_ADD: {
                    Varnode a = def.getInput(0), b = def.getInput(1);
                    if (b.isConstant()) { off += signed(b); v = a; }
                    else if (a.isConstant()) { off += signed(a); v = b; }
                    else return null;
                    break;
                }
                case PcodeOp.INT_SUB:
                    if (!def.getInput(1).isConstant()) return null;
                    off -= signed(def.getInput(1));
                    v = def.getInput(0);
                    break;
                default:
                    return null;
            }
        }
        return null;
    }

    private static long signed(Varnode c) {
        long val = c.getOffset();
        int bits = c.getSize() * 8;
        if (bits > 0 && bits < 64) {
            long sign = 1L << (bits - 1);
            long mask = (1L << bits) - 1;
            val &= mask;
            if ((val & sign) != 0) val -= (1L << bits);
        }
        return val;
    }

    // ---------------------------------------------------------------------
    // Assembly / blocks
    // ---------------------------------------------------------------------

    private JsonArray exportAssembly(Function func, JsonObject stats) {
        JsonArray arr = new JsonArray();
        int count = 0;
        InstructionIterator ii = listing.getInstructions(func.getBody(), true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            if (count < MAX_ASSEMBLY_LINES) {
                arr.add(addr(ins.getAddress()) + ": " + ins.toString());
            }
            count++;
        }
        stats.addProperty("instructions", count);
        return arr;
    }

    private int countBlocks(Function func) {
        try {
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator it = model.getCodeBlocksContaining(func.getBody(), monitor);
            int n = 0;
            while (it.hasNext()) { it.next(); n++; }
            return n;
        } catch (Exception e) {
            return 0;
        }
    }

    // ---------------------------------------------------------------------
    // Call graph
    // ---------------------------------------------------------------------

    private void exportCallGraph(Function func, JsonObject o) {
        Set<String> callers = new TreeSet<>();
        for (Function caller : func.getCallingFunctions(monitor)) {
            Function real = caller.isThunk() ? caller.getThunkedFunction(true) : caller;
            if (real != null && !real.isExternal()) callers.add(addr(real.getEntryPoint()));
        }
        JsonArray callerArr = new JsonArray();
        for (String c : callers) callerArr.add(c);
        o.add("callers", callerArr);

        // `callees` holds internal (non-external) function addresses only;
        // `calls` describes every distinct call target, imports included.
        Set<String> callees = new TreeSet<>();
        Map<String, JsonObject> calls = new TreeMap<>();
        for (Function callee : func.getCalledFunctions(monitor)) {
            Function target = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
            if (target == null) target = callee;
            boolean external = target.isExternal();
            String key = external ? "ext:" + target.getName(true) : addr(target.getEntryPoint());
            if (calls.containsKey(key)) continue;
            JsonObject c = new JsonObject();
            c.addProperty("address", external ? "" : addr(target.getEntryPoint()));
            c.addProperty("name", target.getName(true));
            c.addProperty("external", external);
            if (external) {
                ExternalLocation loc = target.getExternalLocation();
                c.addProperty("library", loc == null ? "" : loc.getLibraryName());
            } else {
                callees.add(addr(target.getEntryPoint()));
            }
            calls.put(key, c);
        }
        JsonArray calleeArr = new JsonArray();
        for (String c : callees) calleeArr.add(c);
        o.add("callees", calleeArr);
        JsonArray callArr = new JsonArray();
        for (JsonObject c : calls.values()) callArr.add(c);
        o.add("calls", callArr);
    }

    private Address resolveThunk(Address target) {
        Function f = getFunctionAt(target);
        if (f != null && f.isThunk()) {
            Function real = f.getThunkedFunction(true);
            if (real != null && !real.isExternal()) return real.getEntryPoint();
        }
        return target;
    }

    // ---------------------------------------------------------------------
    // Strings and globals referenced by the function
    // ---------------------------------------------------------------------

    private void exportDataReferences(Function func, JsonObject o) {
        Set<String> strings = new LinkedHashSet<>();
        Map<String, JsonObject> globals = new TreeMap<>();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        SymbolTable symtab = currentProgram.getSymbolTable();

        InstructionIterator ii = listing.getInstructions(func.getBody(), true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            for (Reference ref : refMgr.getReferencesFrom(ins.getAddress())) {
                RefType rt = ref.getReferenceType();
                if (rt.isFlow() || rt.isCall()) continue;
                Address to = ref.getToAddress();
                if (to.isStackAddress() || to.isRegisterAddress()) continue;

                if (to.isExternalAddress()) {
                    Symbol s = symtab.getPrimarySymbol(to);
                    String name = s == null ? to.toString() : s.getName(true);
                    globals.computeIfAbsent("ext:" + name, k -> globalEntry("", name, "", true, rt));
                    continue;
                }
                if (!to.isMemoryAddress()) continue;
                if (getFunctionContaining(to) != null) continue;

                Data data = listing.getDataContaining(to);
                if (data != null && data.hasStringValue()) {
                    Object val = data.getValue();
                    if (val != null) {
                        String s = val.toString();
                        if (s.length() > 1) strings.add(s);
                    }
                    continue;
                }
                Symbol sym = symtab.getPrimarySymbol(to);
                String name = sym != null ? sym.getName(true) : "DAT_" + to.toString();
                String type = data != null ? data.getDataType().getDisplayName() : "";
                String key = addr(to);
                JsonObject existing = globals.get(key);
                if (existing == null) {
                    globals.put(key, globalEntry(key, name, type, false, rt));
                } else {
                    mergeAccess(existing, rt);
                }
            }
        }

        JsonArray strArr = new JsonArray();
        for (String s : strings) strArr.add(s);
        o.add("strings", strArr);
        JsonArray globArr = new JsonArray();
        for (JsonObject g : globals.values()) globArr.add(g);
        o.add("globals", globArr);
    }

    private JsonObject globalEntry(String address, String name, String type, boolean external, RefType rt) {
        JsonObject g = new JsonObject();
        g.addProperty("address", address);
        g.addProperty("name", name);
        g.addProperty("type", type);
        g.addProperty("external", external);
        g.addProperty("read", rt.isRead() || (!rt.isWrite()));
        g.addProperty("write", rt.isWrite());
        return g;
    }

    private void mergeAccess(JsonObject g, RefType rt) {
        if (rt.isRead()) g.addProperty("read", true);
        if (rt.isWrite()) g.addProperty("write", true);
    }

    // ---------------------------------------------------------------------
    // Whole-program tables
    // ---------------------------------------------------------------------

    private JsonArray exportProgramStrings() {
        JsonArray arr = new JsonArray();
        DataIterator di = listing.getDefinedData(true);
        int n = 0;
        while (di.hasNext() && n < MAX_PROGRAM_STRINGS && !monitor.isCancelled()) {
            Data d = di.next();
            if (!d.hasStringValue()) continue;
            Object val = d.getValue();
            if (val == null) continue;
            JsonObject s = new JsonObject();
            s.addProperty("address", addr(d.getAddress()));
            s.addProperty("value", val.toString());
            arr.add(s);
            n++;
        }
        return arr;
    }

    private JsonArray exportClasses() {
        JsonArray arr = new JsonArray();
        Iterator<GhidraClass> classes = currentProgram.getSymbolTable().getClassNamespaces();
        while (classes.hasNext()) {
            GhidraClass cls = classes.next();
            if (cls.isExternal()) continue;
            JsonObject c = new JsonObject();
            c.addProperty("name", cls.getName(true));
            Structure st = VariableUtilities.findExistingClassStruct(cls, currentProgram.getDataTypeManager());
            JsonArray fields = new JsonArray();
            if (st != null) {
                c.addProperty("size", st.isZeroLength() ? 0 : st.getLength());
                for (DataTypeComponent comp : st.getDefinedComponents()) {
                    JsonObject f = new JsonObject();
                    f.addProperty("offset", comp.getOffset());
                    f.addProperty("size", comp.getLength());
                    f.addProperty("name", comp.getFieldName() == null ? "" : comp.getFieldName());
                    f.addProperty("type", comp.getDataType().getDisplayName());
                    fields.add(f);
                }
            } else {
                c.addProperty("size", 0);
            }
            c.add("fields", fields);
            arr.add(c);
        }
        return arr;
    }

    private static String addr(Address a) {
        return "0x" + Long.toHexString(a.getOffset());
    }
}
