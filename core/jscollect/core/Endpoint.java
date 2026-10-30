package jscollect.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One endpoint: URL + method + export key + module + definition-level data/params
 * targets + the argument fields recovered from each call site.
 *
 * Parameters have two layers of origin:
 *   - definition layer (fields hard-coded in the data/params object literal;
 *     usually empty because the common form is a passthrough `data: e`)
 *   - call site (the place that actually decides the fields: the object the caller passes)
 */
public final class Endpoint {
    public long id;                // monotonic id (ascending = discovery order)
    public final String url;
    public final String method;
    public final String exportKey;   // e.g. fy
    public final String moduleId;    // e.g. 5662
    public final String sourceFile;  // file where the url is defined
    public String dataTarget;        // the "e" in data: e (passthrough), or null
    public String paramsTarget;      // the "t" in params: t, or null
    public List<String> paramFields = new ArrayList<>();   // fields hard-coded at definition layer
    public final List<String> headerFields = new ArrayList<>();  // fields in headers:{...} (header params)
    public int defPos = -1;          // position of the url definition in sourceFile (for evidence)
    public String defSnippet = "";   // short source snippet around defPos (evidence, set by the UI layer)

    public final List<CallSite> callSites = new ArrayList<>();

    public Endpoint(String url, String method, String exportKey, String moduleId, String sourceFile) {
        this.url = url;
        this.method = method;
        this.exportKey = exportKey;
        this.moduleId = moduleId;
        this.sourceFile = sourceFile;
    }

    /** One call site: file + argument fields (field name -> source expression). */
    public static final class CallSite {
        public final String file;
        public final int pos;
        public final Map<String, String> fields = new LinkedHashMap<>();
        public String rawArg = "";

        public CallSite(String file, int pos) {
            this.file = file;
            this.pos = pos;
        }
    }

    /** Union of definition-level params + call-site fields (gated on payload passthrough). */
    public Set<String> allFieldNames() {
        Set<String> out = new LinkedHashSet<>();
        out.addAll(paramFields);
        // Only trust call-site fields when the endpoint actually forwards its argument
        // into the request (data: e / params: e).
        if (dataTarget != null || paramsTarget != null) {
            for (CallSite cs : callSites) out.addAll(cs.fields.keySet());
        }
        return out;
    }

    /** Field name -> literal default value (number/string/boolean), for inline-object call sites. */
    public Map<String, String> paramValues() {
        Map<String, String> out = new LinkedHashMap<>();
        if (dataTarget != null || paramsTarget != null) {
            for (CallSite cs : callSites) {
                for (Map.Entry<String, String> e : cs.fields.entrySet()) {
                    String v = cleanLiteral(e.getValue());
                    if (v != null) out.putIfAbsent(e.getKey(), v);
                }
            }
        }
        return out;
    }

    /** A literal default value (quotes stripped), or null when not a literal. */
    private static String cleanLiteral(String v) {
        if (v == null) return null;
        String s = v.trim();
        if (s.matches("-?\\d+(\\.\\d+)?")) return s;                      // number
        if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            return s.substring(1, s.length() - 1);                        // string
        }
        if (s.equals("true") || s.equals("false")) return s;              // boolean
        return null;                                                       // variable/complex
    }

    /** REST path params embedded in the url: /api/user/:id  or  /api/user/{id}. */
    public Set<String> pathParams() {
        Set<String> out = new LinkedHashSet<>();
        Matcher pp = Pattern.compile("(?::([A-Za-z_$][\\w$]*)|\\{([A-Za-z_$][\\w$]*)\\})").matcher(url);
        while (pp.find()) out.add(pp.group(1) != null ? pp.group(1) : pp.group(2));
        return out;
    }

    @Override
    public String toString() {
        return method + " " + url + "  [" + exportKey + " @" + moduleId + "] "
                + "callSites=" + callSites.size();
    }
}
