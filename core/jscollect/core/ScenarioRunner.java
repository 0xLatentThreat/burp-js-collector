package jscollect.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Data-driven scenario runner. Scans test/scenarios for folders containing an
 * expected.json, feeds each scenario's JS files through Pipeline.analyze, and
 * validates url / method / params / headers / pathParams against the expected
 * spec. Also asserts `forbidden` urls never appear.
 *
 * expected.json schema:
 * {
 *   "name": "...",
 *   "files": ["main.js"],
 *   "gap": false,                     // optional: known feature gap (reported, not failed)
 *   "endpoints": [
 *     {"url": "/api/x", "method": "GET", "params": ["a"], "headers": ["p"], "pathParams": ["id"]}
 *   ],
 *   "forbidden": ["..."]
 * }
 */
public final class ScenarioRunner {

    private static int pass, fail, gap;

    public static void main(String[] args) throws Exception {
        String root = args.length > 0 ? args[0] : "test/scenarios";
        File dir = new File(root);
        if (!dir.isDirectory()) {
            System.err.println("scenarios dir not found: " + dir.getAbsolutePath());
            System.exit(2);
        }
        List<File> scenarioDirs = new ArrayList<>();
        collect(dir, scenarioDirs);
        scenarioDirs.sort(Comparator.comparing(File::getAbsolutePath));

        System.out.println("== ScenarioRunner: " + scenarioDirs.size() + " scenarios in " + dir.getAbsolutePath() + " ==\n");
        for (File sd : scenarioDirs) {
            String report = run(sd);
            System.out.println(report);
        }
        System.out.println("\n== summary: " + pass + " passed, " + fail + " failed, " + gap + " gap ==");
        if (fail > 0) System.exit(1);
    }

    private static void collect(File dir, List<File> out) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            if (k.isDirectory()) {
                if (new File(k, "expected.json").isFile()) out.add(k);
                else collect(k, out);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static String run(File dir) throws Exception {
        String json = new String(Files.readAllBytes(new File(dir, "expected.json").toPath()), StandardCharsets.UTF_8);
        Map<String, Object> exp = (Map<String, Object>) parse(json);
        String name = str(exp, "name");
        boolean isGap = bool(exp, "gap", false);

        Map<String, String> files = new LinkedHashMap<>();
        for (Object f : list(exp, "files")) {
            String rel = (String) f;
            String body = new String(Files.readAllBytes(new File(dir, rel).toPath()), StandardCharsets.UTF_8);
            files.put("https://example.test/" + rel.replace('\\', '/'), body);
        }

        List<Endpoint> eps = Pipeline.analyze(files);

        StringBuilder r = new StringBuilder();
        for (Object eo : list(exp, "endpoints")) {
            Map<String, Object> e = (Map<String, Object>) eo;
            String url = str(e, "url");
            Endpoint found = Pipeline.findByUrl(eps, url);
            if (found == null) {
                r.append("    MISSING ").append(url).append("\n");
                continue;
            }
            if (e.containsKey("method") && !str(e, "method").equals(found.method)) {
                r.append("    method ").append(url).append(": expected ").append(str(e, "method"))
                        .append(" got ").append(found.method).append("\n");
            }
            if (e.containsKey("params")) {
                Set<String> expP = new HashSet<>(strList(e, "params"));
                Set<String> gotP = new HashSet<>(found.allFieldNames());
                if (!expP.equals(gotP)) r.append("    params ").append(url).append(": expected ")
                        .append(expP).append(" got ").append(gotP).append("\n");
            }
            if (e.containsKey("headers")) {
                Set<String> expH = new HashSet<>(strList(e, "headers"));
                Set<String> gotH = new HashSet<>(found.headerFields);
                if (!expH.equals(gotH)) r.append("    headers ").append(url).append(": expected ")
                        .append(expH).append(" got ").append(gotH).append("\n");
            }
            if (e.containsKey("pathParams")) {
                Set<String> expPp = new HashSet<>(strList(e, "pathParams"));
                Set<String> gotPp = new HashSet<>(found.pathParams());
                if (!expPp.equals(gotPp)) r.append("    pathParams ").append(url).append(": expected ")
                        .append(expPp).append(" got ").append(gotPp).append("\n");
            }
            if (e.containsKey("paramValues")) {
                Map<String, String> expV = strMap(e, "paramValues");
                Map<String, String> gotV = found.paramValues();
                if (!expV.equals(gotV)) r.append("    paramValues ").append(url).append(": expected ")
                        .append(expV).append(" got ").append(gotV).append("\n");
            }
        }
        for (Object f : list(exp, "forbidden")) {
            if (Pipeline.findByUrl(eps, (String) f) != null) {
                r.append("    FORBIDDEN present ").append(f).append("\n");
            }
        }

        if (isGap) {
            gap++;
            return "[GAP] " + name + "\n" + r;
        }
        if (r.length() == 0) {
            pass++;
            return "[PASS] " + name;
        }
        fail++;
        return "[FAIL] " + name + "\n" + r;
    }

    // ---- tiny helpers over the parsed JSON ----
    @SuppressWarnings("unchecked")
    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : v.toString();
    }

    private static boolean bool(Map<String, Object> m, String k, boolean def) {
        Object v = m.get(k);
        return v == null ? def : Boolean.TRUE.equals(v);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v == null) return new ArrayList<>();
        return (List<Object>) v;
    }

    private static List<String> strList(Map<String, Object> m, String k) {
        List<String> out = new ArrayList<>();
        for (Object o : list(m, k)) out.add(o.toString());
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> strMap(Map<String, Object> m, String k) {
        Map<String, String> out = new LinkedHashMap<>();
        Object v = m.get(k);
        if (v instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                out.put(e.getKey().toString(), e.getValue() == null ? "" : e.getValue().toString());
            }
        }
        return out;
    }

    // ---- minimal JSON parser ----
    public static Object parse(String s) {
        int[] i = {0};
        Object v = value(s, i);
        ws(s, i);
        if (i[0] != s.length()) throw new RuntimeException("trailing chars at " + i[0]);
        return v;
    }

    private static void ws(String s, int[] i) {
        while (i[0] < s.length() && Character.isWhitespace(s.charAt(i[0]))) i[0]++;
    }

    private static Object value(String s, int[] i) {
        ws(s, i);
        char c = s.charAt(i[0]);
        if (c == '{') return object(s, i);
        if (c == '[') return array(s, i);
        if (c == '"') return string(s, i);
        if (s.startsWith("true", i[0])) { i[0] += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i[0])) { i[0] += 5; return Boolean.FALSE; }
        if (s.startsWith("null", i[0])) { i[0] += 4; return null; }
        return number(s, i);
    }

    private static Map<String, Object> object(String s, int[] i) {
        Map<String, Object> m = new LinkedHashMap<>();
        i[0]++; // {
        ws(s, i);
        if (s.charAt(i[0]) == '}') { i[0]++; return m; }
        while (true) {
            ws(s, i);
            String k = string(s, i);
            ws(s, i);
            i[0]++; // :
            m.put(k, value(s, i));
            ws(s, i);
            char c = s.charAt(i[0]);
            if (c == ',') { i[0]++; continue; }
            if (c == '}') { i[0]++; return m; }
            throw new RuntimeException("bad object at " + i[0]);
        }
    }

    private static List<Object> array(String s, int[] i) {
        List<Object> l = new ArrayList<>();
        i[0]++; // [
        ws(s, i);
        if (s.charAt(i[0]) == ']') { i[0]++; return l; }
        while (true) {
            l.add(value(s, i));
            ws(s, i);
            char c = s.charAt(i[0]);
            if (c == ',') { i[0]++; continue; }
            if (c == ']') { i[0]++; return l; }
            throw new RuntimeException("bad array at " + i[0]);
        }
    }

    private static String string(String s, int[] i) {
        i[0]++; // "
        StringBuilder sb = new StringBuilder();
        while (i[0] < s.length()) {
            char c = s.charAt(i[0]);
            if (c == '"') { i[0]++; return sb.toString(); }
            if (c == '\\') {
                i[0]++;
                char e = s.charAt(i[0]);
                switch (e) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    default: sb.append(e);
                }
                i[0]++;
                continue;
            }
            sb.append(c);
            i[0]++;
        }
        throw new RuntimeException("unterminated string");
    }

    private static Object number(String s, int[] i) {
        int st = i[0];
        while (i[0] < s.length() && "-+0123456789.eE".indexOf(s.charAt(i[0])) >= 0) i[0]++;
        String n = s.substring(st, i[0]);
        if (n.contains(".") || n.contains("e") || n.contains("E")) return Double.parseDouble(n);
        return Long.parseLong(n);
    }
}
