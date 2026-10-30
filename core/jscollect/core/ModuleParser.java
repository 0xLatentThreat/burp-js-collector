package jscollect.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Webpack module boundary splitting + export table parsing.
 *
 * Handles webpack5 (`5662: (e,t,a) => {`) and webpack4 (`"45d1": function(e,t,r){`),
 * and does **not** depend on newlines (works on beautified and single-line minified files).
 */
public final class ModuleParser {

    // webpack5 arrow form:  id: (a,b,req) => {
    private static final Pattern DEF5 = Pattern.compile(
        "(?<![\\w$])(\"?)(\\d{1,6}|[0-9a-zA-Z_$./-]{2,24})\\1\\s*:\\s*"
        + "\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*(\\w+)\\s*\\)\\s*=>\\s*\\{");

    // webpack4 function form:  "id": function(a,b,req){
    private static final Pattern DEF4 = Pattern.compile(
        "(?<![\\w$])(\"?)(\\d{1,6}|[0-9a-zA-Z_$./-]{2,24})\\1\\s*:\\s*"
        + "function\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*(\\w+)\\s*\\)\\s*\\{");

    // Export table:  X.d(t, { k: () => local, ... });
    private static final Pattern EXPORT_BLOCK = Pattern.compile(
        "[A-Za-z_$][\\w$]*\\s*\\.\\s*d\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*,\\s*\\{(.*?)}\\s*\\)",
        Pattern.DOTALL);
    private static final Pattern EXPORT_ITEM = Pattern.compile(
        "(\"[^\"]+\"|[A-Za-z_$][\\w$]*)\\s*:\\s*\\(\\s*\\)\\s*=>\\s*([A-Za-z_$][\\w$]*)");

    // Sequential export:  r.d(t, "key", function(){ return local })  /  r.d(t, "key", () => local)
    private static final Pattern EXPORT_SEQ = Pattern.compile(
        "[A-Za-z_$][\\w$]*\\s*\\.\\s*d\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*,\\s*[\"']([^\"']+)[\"']\\s*,\\s*"
        + "(?:\\(function\\s*\\(\\s*\\)\\s*\\{\\s*return\\s+|function\\s*\\(\\s*\\)\\s*\\{\\s*return\\s+|\\(\\s*\\)\\s*=>\\s*)"
        + "([A-Za-z_$][\\w$]*)");

    // Module import:  local = r("moduleId")
    private static final Pattern IMPORT = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*[A-Za-z_$][\\w$]*\\s*\\(\\s*[\"']([^\"']+)[\"']\\s*\\)");

    // webpack4 CommonJS export:  exports.name = local  /  module.exports.name = local
    private static final Pattern CJS_EXPORT = Pattern.compile(
        "(?:exports|module\\.exports)\\.([A-Za-z_$][\\w$]*)\\s*=\\s*([A-Za-z_$][\\w$]*)");

    private ModuleParser() {}

    /** Split a whole file into modules (ordered by definition position). */
    public static List<Module> split(String js) {
        Map<Integer, String> byStart = new LinkedHashMap<>();
        for (Pattern p : new Pattern[]{DEF5, DEF4}) {
            Matcher m = p.matcher(js);
            while (m.find()) {
                byStart.putIfAbsent(m.start(), m.group(2));
            }
        }
        List<Integer> starts = new ArrayList<>(byStart.keySet());
        starts.sort(Integer::compareTo);

        List<Module> out = new ArrayList<>();
        for (int i = 0; i < starts.size(); i++) {
            int s = starts.get(i);
            int e = (i + 1 < starts.size()) ? starts.get(i + 1) : js.length();
            String id = byStart.get(s);
            String body = js.substring(s, e);
            out.add(new Module(id, body, s, e));
        }
        return out;
    }

    /** Export table within a module: local variable -> export key (quoted keys like default included). */
    public static Map<String, String> exports(String moduleBody) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher blk = EXPORT_BLOCK.matcher(moduleBody);
        while (blk.find()) {
            Matcher it = EXPORT_ITEM.matcher(blk.group(1));
            while (it.find()) {
                out.put(it.group(2), it.group(1).replace("\"", ""));
            }
        }
        // sequential r.d(t, "key", () => local) form
        Matcher seq = EXPORT_SEQ.matcher(moduleBody);
        while (seq.find()) {
            out.putIfAbsent(seq.group(2), seq.group(1));
        }
        // webpack4 CommonJS:  exports.getUser = getUser
        Matcher cjs = CJS_EXPORT.matcher(moduleBody);
        while (cjs.find()) {
            out.putIfAbsent(cjs.group(2), cjs.group(1));
        }
        return out;
    }

    /** Module imports within a module body: local variable -> module id. */
    public static Map<String, String> imports(String moduleBody) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher m = IMPORT.matcher(moduleBody);
        while (m.find()) {
            out.putIfAbsent(m.group(1), m.group(2));
        }
        return out;
    }
}
