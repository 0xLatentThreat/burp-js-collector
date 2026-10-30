package jscollect.core;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Vite / Rollup (ESM) API-layer endpoint extraction.
 *
 * The API layer is written as a flat list of arrow functions wrapping an
 * axios-style instance, with a data/params passthrough and NO webpack export
 * table or module alias:
 *
 *   grantUserAuthorization = e => http({ url:"/jk/health/grantUserAuthorization",
 *                                         method:"post", data:e, headers })
 *
 * Call sites use the same local name directly:  grantUserAuthorization({ ... })
 * or  grantUserAuthorization(someVar).
 */
public final class EsmEndpointExtractor {

    // arrow form: name = param => http({ url, method:"post", data })  OR  name = param => n["a"].post({ url, data })
    private static final Pattern DEF_ARROW = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*[=:]\\s*(?:\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*"
        + "[A-Za-z_$][\\w$]*(?:\\[[^\\]\\n]*\\])?\\s*(?:\\.\\s*(get|post|put|delete|patch))?\\s*\\(\\s*\\{",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // function form:  name = function() { ... return c["a"].post({ url:"...", data:e }) ... }
    private static final Pattern DEF_FUNC = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*[=:]\\s*function\\s*\\(\\s*\\w*\\s*\\)\\s*\\{",
        Pattern.DOTALL);

    private static final Pattern URL = Pattern.compile("url\\s*:\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)");
    private static final Pattern METHOD = Pattern.compile("(?i)method\\s*:\\s*[\"']([A-Za-z]+)[\"']");

    // Vuex store: actions:{ ... } and  actionName: function(ctx, payload) { ... }
    private static final Pattern ACTIONS = Pattern.compile("actions\\s*:\\s*\\{");
    private static final Pattern ACTION_DEF = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{");
    private static final Pattern RETURN_EXPORT_REF = Pattern.compile(
        "return\\s+Object\\(([A-Za-z_$][\\w$]*)\\[[\"']([^\"']+)[\"']\\]\\)\\s*\\(");
    private static final Pattern DISPATCH_REF = Pattern.compile(
        "(?:dispatch|\\$store\\.dispatch)\\s*\\(\\s*[\"']([^\"']+)[\"']");

    private EsmEndpointExtractor() {}

    /** Extract endpoint definitions from ONE file (Step 1 only; no call sites). */
    public static List<Endpoint> extractDefinitionsFrom(String file, String text) {
        List<Endpoint> out = new ArrayList<>();
        for (Pattern p : new Pattern[]{DEF_ARROW, DEF_FUNC}) {
            Matcher d = p.matcher(text);
            while (d.find()) {
                String name = d.group(1);
                int brace = d.end() - 1;   // regex ends with \{
                String url;
                String rawUrl;
                String method;
                String body;
                if (p == DEF_FUNC) {
                    // function form: extract the exact (bounded) body so url/method/data
                    // don't leak across into the NEXT minified function definition.
                    body = WebpackParser.balanced(text, brace, 4000);
                    if (body.isEmpty()) {
                        body = text.substring(brace, Math.min(text.length(), brace + 4000));
                    }
                    Matcher u = URL.matcher(body);
                    if (!u.find()) continue;
                    rawUrl = GenericEndpointExtractor.urlValue(u);
                    url = GenericEndpointExtractor.normalizeTemplate(rawUrl);
                    method = funcMethod(body, u.start());
                } else {
                    String wrapperMethod = d.group(2) != null ? d.group(2).toUpperCase() : null;
                    body = WebpackParser.balanced(text, brace);
                    Matcher u = URL.matcher(body);
                    if (!u.find()) continue;
                    rawUrl = GenericEndpointExtractor.urlValue(u);
                    url = GenericEndpointExtractor.normalizeTemplate(rawUrl);
                    Matcher mm = METHOD.matcher(body);
                    method = wrapperMethod != null ? wrapperMethod
                            : (mm.find() ? mm.group(1).toUpperCase() : "GET");
                }
                if (GenericEndpointExtractor.isNotUrl(url)) continue;
                Endpoint ep = new Endpoint(url, method, name, "-", file);
                ep.defPos = d.start();
                // payload passthrough: data: e / params: e (gate call-site params on this)
                ep.dataTarget = targetOf(body, "data");
                ep.paramsTarget = targetOf(body, "params");
                // template interpolation vars + header field names
                Map<String, String> interp = new LinkedHashMap<>();
                GenericEndpointExtractor.extractInterp(rawUrl, interp);
                ep.paramFields.addAll(interp.keySet());
                ep.headerFields.addAll(headerNamesOf(body));
                out.add(ep);
            }
        }
        return out;
    }

    /** The variable in `key: var` (e.g. the `e` in `data: e`), or null. */
    private static String targetOf(String body, String key) {
        Matcher m = Pattern.compile("(?<![\\w$.])" + key + "\\s*:\\s*([A-Za-z_$][\\w$.]*)").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    /** Field names in `headers: { ... }`, or empty. */
    private static List<String> headerNamesOf(String body) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("headers\\s*:\\s*\\{").matcher(body);
        if (m.find()) {
            String inner = WebpackParser.balanced(body, m.end() - 1);
            if (inner != null && !inner.isEmpty()) {
                out.addAll(EndpointAnalyzer.parseObject(inner).keySet());
            }
        }
        return out;
    }

    /** Match call sites across all files (Step 2); dedups and returns the final list. */
    public static List<Endpoint> matchCallSites(List<Endpoint> endpoints, Map<String, String> files) {
        Map<String, Endpoint> byUrl = new LinkedHashMap<>();
        for (Endpoint ep : endpoints) byUrl.putIfAbsent(ep.url, ep);

        // Vuex action -> API function mapping (per-file): fn -> [actionNames]
        Map<String, List<String>> fnToActions = new LinkedHashMap<>();
        for (Map.Entry<String, String> fe : files.entrySet()) {
            for (Map.Entry<String, String> am : extractActionMap(fe.getValue()).entrySet()) {
                fnToActions.computeIfAbsent(am.getValue(), k -> new ArrayList<>()).add(am.getKey());
            }
        }

        // Build ONE combined regex over all match keys so each file is scanned exactly once.
        Map<String, Endpoint> keyToEp = new LinkedHashMap<>();
        for (Endpoint ep : byUrl.values()) {
            String action = actionName(ep.url);
            if (ep.exportKey.length() >= 3 && !ep.exportKey.equals(action)) {
                keyToEp.putIfAbsent(ep.exportKey, ep);
            }
            if (action != null && !action.isEmpty()) {
                keyToEp.putIfAbsent(action, ep);
            }
            // Vuex actions that forward to this endpoint's API function (e.g. "getServicersList" -> l)
            List<String> actions = fnToActions.get(ep.exportKey);
            if (actions != null) {
                for (String a : actions) keyToEp.putIfAbsent(a, ep);
            }
        }
        List<String> keys = new ArrayList<>(keyToEp.keySet());
        keys.sort((a, b) -> Integer.compare(b.length(), a.length()));   // longest first
        StringBuilder alt = new StringBuilder();
        for (String k : keys) {
            if (alt.length() > 0) alt.append('|');
            alt.append(Pattern.quote(k));
        }
        Pattern combined = alt.length() == 0 ? null
                : Pattern.compile("(?<![\\w$])(" + alt + ")\\s*\\(");

        if (combined != null) {
            for (Map.Entry<String, String> fe : files.entrySet()) {
                String file = fe.getKey();
                String text = fe.getValue();
                Matcher m = combined.matcher(text);
                while (m.find()) {
                    String key = m.group(1);
                    Endpoint ep = keyToEp.get(key);
                    if (ep != null) {
                        ep.callSites.add(EndpointAnalyzer.extractCallSite(
                                file, text, m.start(1) + key.length()));
                    }
                }
            }
        }

        return new ArrayList<>(byUrl.values());
    }

    /** actionName -> apiFunctionName (direct + export refs + multi-hop dispatch chains). */
    private static Map<String, String> extractActionMap(String text) {
        List<Module> modules = ModuleParser.split(text);
        if (modules.isEmpty()) {
            // not a webpack bundle (plain source): treat the whole file as one pseudo-module
            modules = new ArrayList<>();
            modules.add(new Module("-", text, 0, text.length()));
        }
        Map<String, Module> byId = new LinkedHashMap<>();
        for (Module m : modules) byId.put(m.id, m);

        // First pass: collect action bodies + their module imports.
        Map<String, String> actionBodies = new LinkedHashMap<>();
        Map<String, Map<String, String>> actionImports = new LinkedHashMap<>();
        for (Module m : modules) {
            Map<String, String> imports = ModuleParser.imports(m.body);
            Matcher ab = ACTIONS.matcher(m.body);
            while (ab.find()) {
                String block = WebpackParser.balanced(m.body, ab.end() - 1, 20000);
                if (block.isEmpty()) continue;
                Matcher ad = ACTION_DEF.matcher(block);
                while (ad.find()) {
                    int brace = ad.end() - 1;
                    String body = WebpackParser.balanced(block, brace, 4000);
                    if (body.isEmpty()) body = block.substring(brace, Math.min(block.length(), brace + 4000));
                    actionBodies.putIfAbsent(ad.group(1), body);
                    actionImports.putIfAbsent(ad.group(1), imports);
                }
            }
        }

        // Second pass: direct (api fn) or dispatch (another action) targets.
        Map<String, String> direct = new LinkedHashMap<>();
        Map<String, String> dispatch = new LinkedHashMap<>();
        for (Map.Entry<String, String> ae : actionBodies.entrySet()) {
            String fn = apiFnIn(ae.getValue(), actionImports.get(ae.getKey()), byId);
            if (fn != null) direct.put(ae.getKey(), fn);
            else {
                String d = dispatchedAction(ae.getValue());
                if (d != null) dispatch.put(ae.getKey(), d);
            }
        }

        // Third pass: resolve transitively (action -> action -> api fn).
        Map<String, String> out = new LinkedHashMap<>();
        for (String action : actionBodies.keySet()) {
            String fn = resolveAction(action, direct, dispatch, new HashSet<>());
            if (fn != null) out.put(action, fn);
        }
        return out;
    }

    private static String dispatchedAction(String body) {
        Matcher m = DISPATCH_REF.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    private static String resolveAction(String action, Map<String, String> direct,
                                        Map<String, String> dispatch, Set<String> seen) {
        if (!seen.add(action)) return null;   // cycle guard
        String fn = direct.get(action);
        if (fn != null) return fn;
        String next = dispatch.get(action);
        return next != null ? resolveAction(next, direct, dispatch, seen) : null;
    }

    /** Resolve the API function an action body returns (direct or export reference). */
    private static String apiFnIn(String body, Map<String, String> imports, Map<String, Module> byId) {
        // direct: return l(payload)
        Matcher direct = Pattern.compile("return\\s+([A-Za-z_$][\\w$]*)\\s*\\(").matcher(body);
        if (direct.find() && !direct.group(1).equals("Object")) {
            return direct.group(1);
        }
        // export ref: return Object(i["e"])(payload) -> resolve i -> module -> export "e" -> local fn
        Matcher exp = RETURN_EXPORT_REF.matcher(body);
        if (exp.find()) {
            String moduleId = imports.get(exp.group(1));
            if (moduleId != null) {
                Module target = byId.get(moduleId);
                if (target != null) {
                    String key = exp.group(2);
                    for (Map.Entry<String, String> e : ModuleParser.exports(target.body).entrySet()) {
                        if (e.getValue().equals(key)) return e.getKey();
                    }
                }
            }
        }
        return null;
    }

    /** Full extraction (definitions + call sites). */
    public static List<Endpoint> extract(Map<String, String> files) {
        List<Endpoint> eps = new ArrayList<>();
        for (Map.Entry<String, String> fe : files.entrySet()) {
            eps.addAll(extractDefinitionsFrom(fe.getKey(), fe.getValue()));
        }
        return matchCallSites(eps, files);
    }

    /** Last path segment (query stripped), used as the Vuex/action name. */
    private static String actionName(String url) {
        String u = url;
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        int slash = u.lastIndexOf('/');
        String last = slash >= 0 ? u.substring(slash + 1) : u;
        return last.replaceAll("[^A-Za-z0-9_$]", "");
    }

    /** Method of a function-form endpoint: nearest `.method({` before url, else `method:` field. */
    private static String funcMethod(String block, int urlPos) {
        Matcher m = Pattern.compile("\\.(get|post|put|delete|patch)\\s*\\(\\s*\\{", Pattern.CASE_INSENSITIVE)
                .matcher(block);
        String last = null;
        while (m.find() && m.start() < urlPos) last = m.group(1).toUpperCase();
        if (last != null) return last;
        Matcher fm = METHOD.matcher(block.substring(urlPos, Math.min(block.length(), urlPos + 80)));
        return fm.find() ? fm.group(1).toUpperCase() : "GET";
    }
}
