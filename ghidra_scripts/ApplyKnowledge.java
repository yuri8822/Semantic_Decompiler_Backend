// Applies the pipeline's confidence-gated discoveries back into the Ghidra
// program so the decompiler itself produces better pseudocode on the next
// export: class structures, function names/namespaces/calling conventions,
// parameter and local names/types, return types, global names/types, and
// plate comments (which carry the medium-confidence TODO markers).
//
// The plan is produced by knowledge/ghidra_plan.py. Every change is
// individually guarded: a failure is recorded in the report and the rest of
// the plan still applies.
//
// Script args:  <plan.json> <report.json>
//
//@category SemanticDecompiler

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.DuplicateNameException;

import com.google.gson.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ApplyKnowledge extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    private DecompInterface decompiler;
    private DataTypeManager dtm;
    private DataTypeParser parser;
    private final Map<String, Structure> structs = new HashMap<>();
    private final JsonArray applied = new JsonArray();
    private final JsonArray failed = new JsonArray();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            throw new IllegalArgumentException("usage: ApplyKnowledge.java <plan.json> <report.json>");
        }
        JsonObject plan;
        try (Reader r = new InputStreamReader(new FileInputStream(args[0]), StandardCharsets.UTF_8)) {
            plan = JsonParser.parseReader(r).getAsJsonObject();
        }

        dtm = currentProgram.getDataTypeManager();
        parser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);

        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        decompiler = new DecompInterface();
        decompiler.setOptions(opts);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);

        try {
            applyStructs(array(plan, "structs"));
            for (JsonElement e : array(plan, "functions")) {
                applyFunction(e.getAsJsonObject());
            }
            for (JsonElement e : array(plan, "globals")) {
                applyGlobal(e.getAsJsonObject());
            }
        } finally {
            decompiler.dispose();
        }

        JsonObject report = new JsonObject();
        report.add("applied", applied);
        report.add("failed", failed);
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[1]), StandardCharsets.UTF_8)) {
            gson.toJson(report, w);
        }
        println("=== ApplyKnowledge complete: " + applied.size() + " applied, " + failed.size() + " failed ===");
    }

    // ---------------------------------------------------------------------
    // Structures
    // ---------------------------------------------------------------------

    private void applyStructs(JsonArray plans) {
        // Pass 1: make every structure exist at its final size, so fields of
        // one can point at another regardless of plan order.
        for (JsonElement e : plans) {
            JsonObject s = e.getAsJsonObject();
            String name = str(s, "name");
            try {
                GhidraClass cls = getOrCreateClass(name);
                Structure st = VariableUtilities.findOrCreateClassStruct(cls, dtm);
                st = (Structure) dtm.resolve(st, DataTypeConflictHandler.KEEP_HANDLER);
                ensureLength(st, num(s, "size", 0));
                structs.put(name, st);
                ok("struct", name, "size " + st.getLength());
            } catch (Exception ex) {
                fail("struct", name, ex);
            }
        }
        // Pass 2: lay out the fields.
        for (JsonElement e : plans) {
            JsonObject s = e.getAsJsonObject();
            Structure st = structs.get(str(s, "name"));
            if (st == null) continue;
            for (JsonElement fe : array(s, "fields")) {
                JsonObject f = fe.getAsJsonObject();
                String target = st.getName() + "+0x" + Integer.toHexString(num(f, "offset", 0));
                try {
                    applyField(st, f);
                    ok("field", target, str(f, "name"));
                } catch (Exception ex) {
                    fail("field", target, ex);
                }
            }
        }
    }

    private void applyField(Structure st, JsonObject f) throws Exception {
        int offset = num(f, "offset", 0);
        int size = Math.max(1, num(f, "size", 1));
        String name = str(f, "name");
        String comment = str(f, "comment");
        DataType dt = resolveType(str(f, "type"));
        if (dt == null || dt.getLength() <= 0) {
            dt = Undefined.getUndefinedDataType(size);
        }
        int len = dt.getLength();
        ensureLength(st, offset + len);
        for (int o = offset; o < offset + len; o++) {
            st.clearAtOffset(o);
        }
        try {
            st.replaceAtOffset(offset, dt, len, name, comment.isEmpty() ? null : comment);
        } catch (IllegalArgumentException dup) {
            st.replaceAtOffset(offset, dt, len, name + "_" + Integer.toHexString(offset),
                comment.isEmpty() ? null : comment);
        }
    }

    private void ensureLength(Structure st, int size) {
        int current = st.isZeroLength() ? 0 : st.getLength();
        if (size > current) {
            st.growStructure(size - current);
        }
    }

    private GhidraClass getOrCreateClass(String qualified) throws Exception {
        Namespace ns = NamespaceUtils.createNamespaceHierarchy(
            qualified, currentProgram.getGlobalNamespace(), currentProgram, SourceType.USER_DEFINED);
        if (ns instanceof GhidraClass) return (GhidraClass) ns;
        return NamespaceUtils.convertNamespaceToClass(ns);
    }

    // ---------------------------------------------------------------------
    // Functions
    // ---------------------------------------------------------------------

    private void applyFunction(JsonObject f) {
        String address = str(f, "address");
        Function func = getFunctionAt(hexAddress(address));
        if (func == null) {
            failMsg("function", address, "no function at address");
            return;
        }

        if (f.has("name")) {
            try {
                renameFunction(func, str(f, "namespace"), str(f, "name"));
                ok("function", address, func.getName(true));
            } catch (Exception ex) {
                fail("function", address, ex);
            }
        }

        // Switch to __thiscall only while the signature is still the
        // decompiler's own guess: changing the convention after parameters
        // are committed would shift every committed parameter's storage.
        if (bool(f, "thiscall") && !"__thiscall".equals(func.getCallingConventionName())) {
            if (func.getSignatureSource() == SourceType.DEFAULT) {
                try {
                    func.setCallingConvention("__thiscall");
                    ok("calling_convention", address, "__thiscall");
                } catch (Exception ex) {
                    fail("calling_convention", address, ex);
                }
            } else {
                retypeFirstParamAsThis(func, str(f, "namespace"), address);
            }
        }

        if (f.has("comment")) {
            func.setComment(str(f, "comment"));
        }

        for (JsonElement pe : array(f, "params")) {
            JsonObject p = pe.getAsJsonObject();
            String target = address + ":param" + num(p, "index", -1);
            try {
                String result = renameParam(func, p);
                if (result == null) ok("param", target, str(p, "name"));
                else skipped("param", target, result);
            } catch (Exception ex) {
                fail("param", target, ex);
            }
        }

        for (JsonElement le : array(f, "locals")) {
            JsonObject l = le.getAsJsonObject();
            String target = address + ":" + str(l, "old_name");
            try {
                String result = renameLocal(func, l);
                if (result == null) ok("local", target, str(l, "name"));
                else skipped("local", target, result);
            } catch (Exception ex) {
                fail("local", target, ex);
            }
        }

        if (f.has("return_type")) {
            try {
                applyReturnType(func, str(f, "return_type"));
                ok("return_type", address, str(f, "return_type"));
            } catch (Exception ex) {
                fail("return_type", address, ex);
            }
        }
    }

    private void renameFunction(Function func, String namespace, String name) throws Exception {
        Namespace target = currentProgram.getGlobalNamespace();
        if (!namespace.isEmpty()) {
            target = getOrCreateClass(namespace);
        }
        if (!func.getParentNamespace().equals(target)) {
            func.setParentNamespace(target);
        }
        if (!func.getName().equals(name)) {
            try {
                func.setName(name, SourceType.USER_DEFINED);
            } catch (DuplicateNameException dup) {
                func.setName(name + "_" + func.getEntryPoint().toString(), SourceType.USER_DEFINED);
            }
        }
    }

    private void retypeFirstParamAsThis(Function func, String namespace, String address) {
        try {
            Structure st = structs.get(namespace);
            if (st == null) {
                st = (Structure) dtm.resolve(
                    VariableUtilities.findOrCreateClassStruct(getOrCreateClass(namespace), dtm),
                    DataTypeConflictHandler.KEEP_HANDLER);
            }
            HighFunction hf = decompile(func);
            HighSymbol first = hf.getLocalSymbolMap().getNumParams() > 0
                ? hf.getLocalSymbolMap().getParamSymbol(0) : null;
            if (first == null) {
                failMsg("this_param", address, "function has no parameters");
                return;
            }
            DataType ptr = dtm.getPointer(st);
            try {
                HighFunctionDBUtil.updateDBVariable(first, Function.THIS_PARAM_NAME, ptr, SourceType.USER_DEFINED);
            } catch (Exception reserved) {
                HighFunctionDBUtil.updateDBVariable(first, "self", ptr, SourceType.USER_DEFINED);
            }
            ok("this_param", address, namespace + " *");
        } catch (Exception ex) {
            fail("this_param", address, ex);
        }
    }

    /** Returns null on success, or a reason the rename was skipped. */
    private String renameParam(Function func, JsonObject p) throws Exception {
        HighFunction hf = decompile(func);
        int index = num(p, "index", -1);
        if (index < 0 || index >= hf.getLocalSymbolMap().getNumParams()) return "no parameter at index " + index;
        HighSymbol sym = hf.getLocalSymbolMap().getParamSymbol(index);
        if (sym == null) return "no parameter at index " + index;
        if (sym.isThisPointer()) return "auto 'this' parameter is typed through its class";
        String oldName = str(p, "old_name");
        String newName = str(p, "name");
        if (!oldName.isEmpty() && !sym.getName().equals(oldName) && !sym.getName().equals(newName)) {
            return "stale: parameter is now named " + sym.getName();
        }
        DataType dt = p.has("type") ? resolveType(str(p, "type")) : null;
        if (sym.getName().equals(newName) && dt == null) return "already applied";
        HighFunctionDBUtil.updateDBVariable(sym, newName, dt, SourceType.USER_DEFINED);
        return null;
    }

    private String renameLocal(Function func, JsonObject l) throws Exception {
        HighFunction hf = decompile(func);
        String oldName = str(l, "old_name");
        HighSymbol sym = hf.getLocalSymbolMap().getNameToSymbolMap().get(oldName);
        if (sym == null) return "no local named " + oldName + " in current decompilation";
        if (sym.isParameter()) return oldName + " is a parameter";
        DataType dt = l.has("type") ? resolveType(str(l, "type")) : null;
        HighFunctionDBUtil.updateDBVariable(sym, str(l, "name"), dt, SourceType.USER_DEFINED);
        return null;
    }

    private void applyReturnType(Function func, String type) throws Exception {
        DataType dt = resolveType(type);
        if (dt == null) throw new InvalidDataTypeException("cannot resolve type '" + type + "'");
        if (func.getSignatureSource() == SourceType.DEFAULT) {
            // Lock in the decompiler's parameters first; setting only the
            // return type on an uncommitted signature would drop them.
            HighFunctionDBUtil.commitParamsToDatabase(decompile(func), true,
                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
        }
        func.setReturnType(dt, SourceType.USER_DEFINED);
    }

    private HighFunction decompile(Function func) throws Exception {
        DecompileResults res = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);
        if (res == null || !res.decompileCompleted() || res.getHighFunction() == null) {
            throw new IllegalStateException("decompile failed: " + (res == null ? "" : res.getErrorMessage()));
        }
        return res.getHighFunction();
    }

    // ---------------------------------------------------------------------
    // Globals
    // ---------------------------------------------------------------------

    private void applyGlobal(JsonObject g) {
        String address = str(g, "address");
        try {
            Address a = hexAddress(address);
            String name = str(g, "name");
            Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(a);
            if (sym == null || sym.getSource() == SourceType.DEFAULT) {
                createLabel(a, name, true, SourceType.USER_DEFINED);
            } else if (!sym.getName().equals(name)) {
                sym.setName(name, SourceType.USER_DEFINED);
            }
            if (g.has("type")) {
                DataType dt = resolveType(str(g, "type"));
                if (dt != null && dt.getLength() > 0) {
                    DataUtilities.createData(currentProgram, a, dt, -1, false,
                        DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
                }
            }
            ok("global", address, name);
        } catch (Exception ex) {
            fail("global", address, ex);
        }
    }

    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    /**
     * Resolves "Player", "Player *", "char * *", "uint", "longlong"... to a
     * Ghidra data type. Structures created by this plan take priority over
     * same-named types elsewhere. Returns null when the type is unknown.
     */
    private DataType resolveType(String type) {
        if (type == null) return null;
        String t = type.trim();
        if (t.isEmpty()) return null;
        int pointers = 0;
        while (t.endsWith("*")) {
            pointers++;
            t = t.substring(0, t.length() - 1).trim();
        }
        DataType base = structs.get(t);
        if (base == null) {
            try {
                base = parser.parse(t);
            } catch (Exception ex) {
                base = null;
            }
        }
        if (base == null) {
            if (pointers == 0) return null;
            base = VoidDataType.dataType;
        }
        DataType dt = base;
        for (int i = 0; i < pointers; i++) {
            dt = dtm.getPointer(dt);
        }
        return dt;
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private Address hexAddress(String hex) {
        String h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        return toAddr(Long.parseUnsignedLong(h, 16));
    }

    private static JsonArray array(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonArray() ? o.getAsJsonArray(key) : new JsonArray();
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : "";
    }

    private static int num(JsonObject o, String key, int dflt) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsInt() : dflt;
    }

    private static boolean bool(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() && o.get(key).getAsBoolean();
    }

    private void ok(String kind, String target, String detail) {
        JsonObject o = new JsonObject();
        o.addProperty("kind", kind);
        o.addProperty("target", target);
        o.addProperty("detail", detail);
        applied.add(o);
    }

    private void skipped(String kind, String target, String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("kind", kind);
        o.addProperty("target", target);
        o.addProperty("detail", "skipped: " + reason);
        applied.add(o);
    }

    private void fail(String kind, String target, Exception ex) {
        failMsg(kind, target, ex.getClass().getSimpleName() + ": " + ex.getMessage());
    }

    private void failMsg(String kind, String target, String error) {
        JsonObject o = new JsonObject();
        o.addProperty("kind", kind);
        o.addProperty("target", target);
        o.addProperty("error", error);
        failed.add(o);
        println("WARNING: " + kind + " " + target + ": " + error);
    }
}
