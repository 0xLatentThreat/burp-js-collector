package jscollect.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Endpoint + parameter analysis (Java port of analyze_api_usage.py):
 *
 *   1. Split each file into modules and read the export table (local -> export key)
 *   2. In modules containing url:, extract endpoint defs: url / method / data|params target
 *   3. Build a per-file alias table (alias = x(moduleId))
 *   4. For each endpoint's export key, find cross-file "alias.exportKey(...)" call sites
 *      and extract the argument object's fields
 *
 * Input: Map<file path, JS body> (bodies should already have the HTTP header stripped).
 */
public final class EndpointAnalyzer {

    // Endpoint def:  local = param => (0, ns.W)({ ... })   (param may be `x`, `(x)` or `()`)
    private static final Pattern ARROW_CFG = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*(?:\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)|\\(\\s*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*"
        + "\\(\\s*0\\s*,\\s*[A-Za-z_$][\\w$]*\\.[A-Za-z_$][\\w$]*\\s*\\)\\s*\\(",
        Pattern.DOTALL);
    // Endpoint def (block body):  local = param => { ... url:"..." ... }
    private static final Pattern BLOCK_CFG = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*(?:\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)|\\(\\s*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*\\{",
        Pattern.DOTALL);
    // webpack4 endpoint def:  local = function(param) { return ns.method({ ... }) }
    private static final Pattern WP4_CFG = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*function\\s*\\(\\s*\\w*\\s*\\)\\s*\\{\\s*return\\s*"
        + "[A-Za-z_$][\\w$]*\\.[A-Za-z_$][\\w$]*\\s*\\(",
        Pattern.DOTALL);
    // Alias table:  alias = x(123)  or  alias = require("./id")   (one combined pass)
    private static final Pattern ALIAS = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*[A-Za-z_$][\\w$]*\\s*\\(\\s*(\\d{1,6}|[\"']([^\"']+)[\"'])\\s*\\)");

    private static final Pattern METHOD = Pattern.compile("method\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern URL = Pattern.compile("url\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern DATA_TARGET = Pattern.compile("(?<![\\w$.])data\\s*:\\s*([A-Za-z_$][\\w$.]*)");
    private static final Pattern PARAMS_TARGET = Pattern.compile("(?<![\\w$.])params\\s*:\\s*([A-Za-z_$][\\w$.]*)");

    private EndpointAnalyzer() {}

    /** Extract endpoint definitions from ONE file (Step 1 only; no call sites). */
    public static List<Endpoint> extractDefinitionsFrom(String file, String text) {
        List<Endpoint> out = new ArrayList<>();
        for (Module mod : ModuleParser.split(text)) {
            Map<String, String> exports = ModuleParser.exports(mod.body);
            for (Endpoint ep : defsInModule(mod, exports, file)) {
                out.add(ep);
            }
        }
        return out;
    }

    /** Cross-file call-site matching (Step 2); dedups and returns the final list. */
    public static List<Endpoint> matchCallSites(List<Endpoint> endpoints, Map<String, String> files) {
        Map<String, Endpoint> byUrl = new LinkedHashMap<>();
        for (Endpoint ep : endpoints) byUrl.putIfAbsent(ep.url, ep);
        if (byUrl.isEmpty()) return new ArrayList<>();

        for (Map.Entry<String, String> fe : files.entrySet()) {
            String file = fe.getKey();
            String text = fe.getValue();
            Map<String, String> alias = aliasMap(text);
            for (Endpoint ep : byUrl.values()) {
                String pat = "(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*\\.\\s*"
                        + Pattern.quote(ep.exportKey) + "\\b";
                Matcher m = Pattern.compile(pat).matcher(text);
                while (m.find()) {
                    if (!ep.moduleId.equals(alias.get(m.group(1)))) continue;
                    ep.callSites.add(extractCallSite(file, text, m.end()));
                }
            }
        }

        return new ArrayList<>(byUrl.values());
    }

    /** Full analysis (definitions + call sites). */
    public static List<Endpoint> analyze(Map<String, String> files) {
        List<Endpoint> eps = new ArrayList<>();
        for (Map.Entry<String, String> fe : files.entrySet()) {
            eps.addAll(extractDefinitionsFrom(fe.getKey(), fe.getValue()));
        }
        return matchCallSites(eps, files);
    }

    /** Endpoint definitions within one module. */
    private static List<Endpoint> defsInModule(Module mod, Map<String, String> exports, String file) {
        List<Endpoint> out = new ArrayList<>();
        // arrow-form config
        Matcher a = ARROW_CFG.matcher(mod.body);
        while (a.find()) {
            int brace = mod.body.indexOf('{', a.end());
            if (brace < 0 || brace - a.end() > 8) continue;   // not immediately followed by "{"
            String cfg = WebpackParser.balanced(mod.body, brace);
            Endpoint ep = build(mod, exports, file, a.group(1), cfg);
            if (ep != null) out.add(ep);
        }
        // block-body config (only keep those whose body contains url:)
        Matcher b = BLOCK_CFG.matcher(mod.body);
        while (b.find()) {
            int brace = b.end() - 1;   // regex ends with \{
            String body = WebpackParser.balanced(mod.body, brace);
            if (URL.matcher(body).find()) {
                Endpoint ep = build(mod, exports, file, b.group(1), body);
                if (ep != null) out.add(ep);
            }
        }
        // webpack4 function-form config
        Matcher w = WP4_CFG.matcher(mod.body);
        while (w.find()) {
            int brace = mod.body.indexOf('{', w.end());
            if (brace < 0 || brace - w.end() > 8) continue;
            String cfg = WebpackParser.balanced(mod.body, brace);
            Endpoint ep = build(mod, exports, file, w.group(1), cfg);
            if (ep != null) out.add(ep);
        }
        return out;
    }

    private static Endpoint build(Module mod, Map<String, String> exports, String file,
                                  String local, String cfg) {
        Matcher mu = URL.matcher(cfg);
        if (!mu.find()) return null;
        Matcher mm = METHOD.matcher(cfg);
        String method = mm.find() ? mm.group(1) : "GET";
        String exportKey = exports.getOrDefault(local, local);
        Endpoint ep = new Endpoint(mu.group(1), method, exportKey, mod.id, file);
        Matcher dt = DATA_TARGET.matcher(cfg);
        if (dt.find()) ep.dataTarget = dt.group(1);
        Matcher pt = PARAMS_TARGET.matcher(cfg);
        if (pt.find()) ep.paramsTarget = pt.group(1);
        // fields hard-coded at definition layer (params: { ... } / data: { ... })
        for (String key : new String[]{"params", "data"}) {
            Matcher obj = Pattern.compile("(?<![\\w$.])" + key + "\\s*:\\s*\\{").matcher(cfg);
            if (obj.find()) {
                ep.paramFields.addAll(parseObject(WebpackParser.balanced(cfg, obj.end() - 1)).keySet());
            }
        }
        return ep;
    }

    /** Per-file alias -> moduleId (numeric webpack5 + string webpack4). */
    private static Map<String, String> aliasMap(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher m = ALIAS.matcher(text);
        while (m.find()) {
            String id = m.group(3) != null ? m.group(3) : m.group(2);
            out.putIfAbsent(m.group(1), id);
        }
        return out;
    }

    /** Extract the argument after .key at a call site; try to reduce it to a field map. */
    static Endpoint.CallSite extractCallSite(String file, String text, int afterKey) {
        Endpoint.CallSite cs = new Endpoint.CallSite(file, afterKey);
        int paren = text.indexOf('(', afterKey);
        if (paren < 0 || paren - afterKey > 40) return cs;
        String arg = WebpackParser.balanced(text, paren).trim();
        arg = arg.replaceAll("\\s+", " ");
        if (arg.isEmpty()) return cs;

        if (arg.matches("[A-Za-z_$][\\w$]*")) {
            // bare identifier: search backwards for  ident = { ... }
            int back = Math.max(0, afterKey - 4000);
            Matcher m = Pattern.compile("\\b" + Pattern.quote(arg) + "\\s*=\\s*\\{")
                    .matcher(text.substring(back, afterKey));
            int objBrace = -1;
            int abs = -1;
            while (m.find()) { objBrace = m.end() - 1; abs = back + objBrace; }
            if (objBrace >= 0) {
                cs.fields.putAll(parseObject(WebpackParser.balanced(text, abs)));
            } else {
                cs.rawArg = arg;
                // Fallback: infer fields from `ident.<field>` property accesses nearby
                // (covers `fn(param)` where param is a function argument, e.g. Vite call sites).
                int fb = Math.max(0, afterKey - 2500);
                int ff = Math.min(text.length(), afterKey + 2500);
                Matcher pm = Pattern.compile("\\b" + Pattern.quote(arg) + "\\.([A-Za-z_$][\\w$]*)")
                        .matcher(text.substring(fb, ff));
                while (pm.find()) cs.fields.putIfAbsent(pm.group(1), pm.group(1));
            }
        } else if (arg.startsWith("{")) {
            // balanced() returned the object WITH its braces; parseObject wants them stripped.
            String inner = arg.endsWith("}") ? arg.substring(1, arg.length() - 1) : arg;
            cs.fields.putAll(parseObject(inner));
        } else {
            cs.rawArg = arg;
            // merge-chain fallback: l(l({},a), {}, {fields}) -> last top-level object literal
            String last = lastTopLevelObject(arg);
            if (last != null && !last.isEmpty()) {
                cs.fields.putAll(parseObject(last));
            }
        }
        return cs;
    }

    /** Return the inner text of the last top-level `{...}` in a complex arg (e.g. a merge chain). */
    private static String lastTopLevelObject(String arg) {
        int objDepth = 0;
        char quote = 0;
        int lastBrace = -1;
        for (int i = 0; i < arg.length(); i++) {
            char c = arg.charAt(i);
            if (quote != 0) {
                if (c == '\\') { i++; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') { quote = c; continue; }
            if (c == '{') {
                if (objDepth == 0) lastBrace = i;
                objDepth++;
            } else if (c == '}') {
                objDepth--;
            }
        }
        return lastBrace >= 0 ? WebpackParser.balanced(arg, lastBrace) : null;
    }

    /** Parse a top-level object literal `a:1, b:{x:2}, c:"s"` -> field name -> source expression. */
    static Map<String, String> parseObject(String obj) {
        Map<String, String> out = new LinkedHashMap<>();
        int depth = 0, segStart = 0;
        char quote = 0;
        for (int i = 0; i < obj.length(); i++) {
            char c = obj.charAt(i);
            if (quote != 0) {
                if (c == '\\') { i++; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') { quote = c; continue; }
            if (c == '{' || c == '[' || c == '(') depth++;
            else if (c == '}' || c == ']' || c == ')') depth--;
            else if (c == ',' && depth == 0) {
                putField(out, obj.substring(segStart, i));
                segStart = i + 1;
            }
        }
        putField(out, obj.substring(segStart));
        return out;
    }

    private static void putField(Map<String, String> out, String seg) {
        int colon = topLevelColon(seg);
        if (colon < 0) return;
        String key = seg.substring(0, colon).trim().replaceAll("^[\"']|[\"']$", "");
        String val = seg.substring(colon + 1).trim();
        if (!key.isEmpty()) out.put(key, val);
    }

    private static int topLevelColon(String s) {
        int depth = 0;
        char quote = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (c == '\\') { i++; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') { quote = c; continue; }
            if (c == '{' || c == '[' || c == '(') depth++;
            else if (c == '}' || c == ']' || c == ')') depth--;
            else if (c == ':' && depth == 0) return i;
        }
        return -1;
    }
}
