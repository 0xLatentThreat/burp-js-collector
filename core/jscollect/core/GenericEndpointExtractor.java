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
 * Generic endpoint extraction for endpoints written DIRECTLY in JS (not through
 * the webpack API-layer module pattern handled by EndpointAnalyzer):
 * axios / fetch / jQuery ajax / XHR.open / bare `url:"..."`.
 */
public final class GenericEndpointExtractor {

    /** One extracted endpoint. url is the raw captured string (relative or absolute). */
    public static final class Hit {
        public final String url;
        public final String method;    // GET / POST / ...
        public final String wrapper;   // e.g. "axios.get", "fetch", "ajax", "xhr", "url"
        public final Map<String, String> params = new LinkedHashMap<>();
        public final List<String> headers = new ArrayList<>();   // field names in headers:{...}
        public int pos = -1;           // position of the url match in the source (evidence)

        public Hit(String url, String method, String wrapper) {
            this.url = url;
            this.method = method;
            this.wrapper = wrapper;
        }
    }

    // axios / $axios / $http / request / $request / service / client / api .get|post|put|delete|patch("url" + id, ...)
    private static final Pattern AXIOS = Pattern.compile(
        "(?:\\baxios|\\$axios|\\$http|\\brequest|\\$request|\\bservice|\\bclient|\\bapi)\\s*\\.\\s*(get|post|put|delete|patch)\\s*\\(\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)(\\s*\\+\\s*([A-Za-z_$][\\w$]*))?",
        Pattern.CASE_INSENSITIVE);

    // fetch("url", ...)
    private static final Pattern FETCH = Pattern.compile(
        "(?<![\\w$.])fetch\\s*\\(\\s*[\"']([^\"']+)[\"']");

    // $.ajax({ url:"...", type:"...", data:{...} })
    private static final Pattern JQ_AJAX = Pattern.compile("\\$\\.ajax\\s*\\(\\s*\\{");

    // $.get / $.post / $.getJSON("url", ...)
    private static final Pattern JQ_GETPOST = Pattern.compile(
        "\\$\\.(get|post|getJSON)\\s*\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    // xhr.open("METHOD", "url")
    private static final Pattern XHR = Pattern.compile(
        "\\.open\\s*\\(\\s*[\"'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[\"']\\s*,\\s*[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE);

    // navigator.sendBeacon("url", data)
    private static final Pattern BEACON = Pattern.compile(
        "(?<![\\w$])sendBeacon\\s*\\(\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)");

    // new EventSource("url")
    private static final Pattern EVENT_SOURCE = Pattern.compile(
        "new\\s+EventSource\\s*\\(\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)");

    // new WebSocket("ws://...")
    private static final Pattern WEBSOCKET = Pattern.compile(
        "new\\s+WebSocket\\s*\\(\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)");

    // axios instance: NAME = axios.create({ baseURL: "..." })
    private static final Pattern AXIOS_CREATE = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\s*=\\s*(?:axios|\\$axios|\\$http)\\.create\\s*\\(\\s*\\{");
    private static final Pattern BASEURL_FIELD = Pattern.compile(
        "baseURL\\s*:\\s*[\"']([^\"']*)[\"']");

    // instance method call: NAME.get("url")  (resolved against its baseURL)
    private static final Pattern INSTANCE_METHOD = Pattern.compile(
        "(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*\\.\\s*(get|post|put|delete|patch)\\s*\\(\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)",
        Pattern.CASE_INSENSITIVE);

    // FormData: fd = new FormData();  fd.append("file", f)
    private static final Pattern APPEND_FIELD = Pattern.compile(
        "([A-Za-z_$][\\w$]*)\\.append\\s*\\(\\s*[\"']([^\"']+)[\"']");

    // anyObj.get|post|put|delete|patch({ url:"...", data:... })  (axios instances, n["a"].post, etc.)
    private static final Pattern HTTP_CFG = Pattern.compile(
        "\\.(get|post|put|delete|patch)\\s*\\(\\s*\\{", Pattern.CASE_INSENSITIVE);

    private static final Pattern URL_FIELD = Pattern.compile(
        "(?<![\\w$])url\\s*:\\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`)");
    private static final Pattern INTERP = Pattern.compile("\\$\\{([^}]*)\\}");
    private static final Pattern TYPE_FIELD = Pattern.compile(
        "(?<![\\w$])(?:method|type)\\s*:\\s*[\"'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[\"']",
        Pattern.CASE_INSENSITIVE);

    private GenericEndpointExtractor() {}

    public static List<Hit> extract(String js) {
        List<Hit> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Map<String, List<String>> fdFields = extractFormData(js);

        Matcher ax = AXIOS.matcher(js);
        while (ax.find()) {
            // AXIOS groups: 1=method, 2=double, 3=single, 4=backtick, 5=concat-expr, 6=paramVar
            String rawUrl = ax.group(2) != null ? ax.group(2) : ax.group(3) != null ? ax.group(3) : ax.group(4);
            String concatVar = ax.group(6);
            if (concatVar != null && !concatVar.isEmpty()) {
                if (!rawUrl.endsWith("/") && !rawUrl.isEmpty()) rawUrl += "/";
                rawUrl += "{}";
            }
            Hit h = new Hit(normalizeTemplate(rawUrl), ax.group(1).toUpperCase(),
                    "axios." + ax.group(1).toLowerCase());
            if (concatVar != null && !concatVar.isEmpty()) {
                h.params.put(concatVar, concatVar);
            }
            extractInterp(rawUrl, h.params);
            extractArgParams(js, ax.end(), h, fdFields);
            out.add(h);
        }

        Matcher fe = FETCH.matcher(js);
        while (fe.find()) {
            out.add(fetchHit(js, fe));
        }

        Matcher aj = JQ_AJAX.matcher(js);
        while (aj.find()) {
            String obj = WebpackParser.balanced(js, aj.end() - 1);
            Matcher u = URL_FIELD.matcher(obj);
            if (u.find()) {
                Matcher t = TYPE_FIELD.matcher(obj);
                String method = t.find() ? t.group(1).toUpperCase() : "GET";
                Hit h = new Hit(normalizeTemplate(urlValue(u)), method, "ajax");
                extractInterp(urlValue(u), h.params);
                extractConfigFields(obj, h);
                out.add(h);
            }
        }

        Matcher jg = JQ_GETPOST.matcher(js);
        while (jg.find()) {
            String m = jg.group(1).equalsIgnoreCase("getJSON") ? "GET" : jg.group(1).toUpperCase();
            Hit h = new Hit(jg.group(2), m, "ajax." + jg.group(1).toLowerCase());
            extractArgParams(js, jg.end(), h, fdFields);
            out.add(h);
        }

        Matcher xh = XHR.matcher(js);
        while (xh.find()) {
            out.add(new Hit(xh.group(2), xh.group(1).toUpperCase(), "xhr"));
            seen.add(xh.group(2));
        }

        // navigator.sendBeacon(url, data)  -> POST
        Matcher be = BEACON.matcher(js);
        while (be.find()) {
            String raw = urlValue(be);
            Hit h = new Hit(normalizeTemplate(raw), "POST", "sendBeacon");
            extractInterp(raw, h.params);
            extractArgParams(js, be.end(), h, fdFields);
            out.add(h);
        }

        // new EventSource("url")  -> GET stream
        Matcher es = EVENT_SOURCE.matcher(js);
        while (es.find()) {
            out.add(new Hit(normalizeTemplate(urlValue(es)), "GET", "eventsource"));
        }

        // new WebSocket("ws://...")  -> WS
        Matcher ws = WEBSOCKET.matcher(js);
        while (ws.find()) {
            out.add(new Hit(normalizeTemplate(urlValue(ws)), "WS", "websocket"));
        }

        // axios instance baseURL resolution: api = axios.create({baseURL:"/api"}); api.get("/user") -> /api/user
        Map<String, String> baseUrls = new LinkedHashMap<>();
        Matcher ac = AXIOS_CREATE.matcher(js);
        while (ac.find()) {
            String instance = ac.group(1);
            String obj = WebpackParser.balanced(js, ac.end() - 1);
            String base = "";
            Matcher bf = BASEURL_FIELD.matcher(obj);
            if (bf.find()) base = bf.group(1);
            baseUrls.put(instance, base);
        }
        if (!baseUrls.isEmpty()) {
            Matcher im = INSTANCE_METHOD.matcher(js);
            while (im.find()) {
                String instance = im.group(1);
                String base = baseUrls.get(instance);
                if (base == null) continue;
                String raw = im.group(3) != null ? im.group(3) : im.group(4) != null ? im.group(4) : im.group(5);
                Hit h = new Hit(resolveBase(base, normalizeTemplate(raw)), im.group(2).toUpperCase(), "instance");
                extractInterp(raw, h.params);
                extractArgParams(js, im.end(), h, fdFields);
                out.add(h);
            }
        }

        // anyObj.method({ url:"...", data:... })
        Matcher hc = HTTP_CFG.matcher(js);
        while (hc.find()) {
            String method = hc.group(1).toUpperCase();
            String obj = WebpackParser.balanced(js, hc.end() - 1);
            Matcher u = URL_FIELD.matcher(obj);
            if (u.find()) {
                Hit h = new Hit(normalizeTemplate(urlValue(u)), method, "http." + hc.group(1).toLowerCase());
                extractInterp(urlValue(u), h.params);
                extractConfigFields(obj, h);
                out.add(h);
                seen.add(urlValue(u));
            }
        }

        Matcher uf = URL_FIELD.matcher(js);
        while (uf.find()) {
            String rawUrl = urlValue(uf);
            if (rawUrl == null || rawUrl.isEmpty()) continue;
            if (!seen.add(rawUrl)) continue;   // already captured with a better method/context
            Hit h = new Hit(normalizeTemplate(rawUrl), nearbyMethod(js, uf.start(), uf.end()), "url");
            h.pos = uf.start();
            extractInterp(rawUrl, h.params);
            extractConfigData(js, uf.start(), uf.end(), h);
            out.add(h);
        }

        return out;
    }

    /** fetch(url, { method, body }) -> Hit with the real method + body params. */
    private static Hit fetchHit(String js, Matcher fe) {
        String url = fe.group(1);
        String method = "GET";
        Map<String, String> params = new LinkedHashMap<>();
        int i = skipWs(js, fe.end());
        if (i < js.length() && js.charAt(i) == ',') {   // only then is there an options arg
            int brace = js.indexOf('{', i);
            if (brace >= 0 && brace - i < 60) {
                String obj = WebpackParser.balanced(js, brace);
                if (!obj.isEmpty()) {
                    Matcher tm = Pattern.compile("(?i)method\\s*:\\s*[\"']([A-Za-z]+)[\"']").matcher(obj);
                    if (tm.find()) method = tm.group(1).toUpperCase();
                    Matcher bm = Pattern.compile("(?i)body\\s*:\\s*(.+)", Pattern.DOTALL).matcher(obj);
                    if (bm.find()) {
                        String bodyVal = bm.group(1).trim();
                        String inner = null;
                        if (bodyVal.startsWith("JSON.stringify(")) {
                            int p = bodyVal.indexOf('(');
                            if (p >= 0) inner = WebpackParser.balanced(bodyVal, p);
                        } else if (bodyVal.startsWith("{")) {
                            inner = bodyVal;
                        }
                        if (inner != null && inner.startsWith("{") && inner.endsWith("}")) {
                            params.putAll(EndpointAnalyzer.parseObject(inner.substring(1, inner.length() - 1)));
                        }
                    }
                }
            }
        }
        Hit h = new Hit(url, method, "fetch");
        h.params.putAll(params);
        return h;
    }

    private static int skipWs(String js, int from) {
        int i = from;
        while (i < js.length() && Character.isWhitespace(js.charAt(i))) i++;
        return i;
    }

    /** Nearest `method:`/`type:` around a bare `url:` field (forward, then backward). */
    private static String nearbyMethod(String js, int urlStart, int urlEnd) {
        Matcher fw = TYPE_FIELD.matcher(js.substring(urlEnd, Math.min(js.length(), urlEnd + 120)));
        if (fw.find()) return fw.group(1).toUpperCase();
        // method may come BEFORE url:  axios({ method:"post", ..., url:"..." })
        Matcher bw = TYPE_FIELD.matcher(js.substring(Math.max(0, urlStart - 200), urlStart));
        String last = null;
        while (bw.find()) last = bw.group(1);
        return last != null ? last.toUpperCase() : "GET";
    }

    /** Extract `data:`/`params:`/`headers:` object around a `url:` field (forward + backward window). */
    private static void extractConfigData(String js, int urlStart, int urlEnd, Hit h) {
        extractConfigFrom(js.substring(urlEnd, Math.min(js.length(), urlEnd + 300)), h);
        extractConfigFrom(js.substring(Math.max(0, urlStart - 300), urlStart), h);
    }

    private static void extractConfigFrom(String window, Hit h) {
        Matcher dm = Pattern.compile("(?<![\\w$])(data|params|headers)\\s*:\\s*\\{").matcher(window);
        while (dm.find()) {
            String key = dm.group(1);
            String inner = WebpackParser.balanced(window, dm.end() - 1);
            if (inner == null || inner.isEmpty()) continue;
            if (key.equals("headers")) {
                h.headers.addAll(EndpointAnalyzer.parseObject(inner).keySet());
            } else {
                h.params.putAll(EndpointAnalyzer.parseObject(inner));
            }
        }
    }

    /** data/params/headers from an already-balanced config object (axios/ajax config). */
    private static void extractConfigFields(String obj, Hit h) {
        Map<String, String> fields = EndpointAnalyzer.parseObject(obj);
        String data = fields.get("data");
        if (data != null && data.trim().startsWith("{")) h.params.putAll(parseNested(data));
        String params = fields.get("params");
        if (params != null && params.trim().startsWith("{")) h.params.putAll(parseNested(params));
        String headers = fields.get("headers");
        if (headers != null && headers.trim().startsWith("{")) h.headers.addAll(parseNested(headers).keySet());
    }

    /** Best-effort params: the object literal argument after the url (axios-style), or a FormData var. */
    private static void extractArgParams(String js, int afterUrl, Hit h, Map<String, List<String>> fdFields) {
        int i = skipWs(js, afterUrl);
        if (i >= js.length() || js.charAt(i) != ',') return;   // no options argument
        int j = skipWs(js, i + 1);
        // bare identifier -> FormData var fields
        if (j < js.length() && (Character.isJavaIdentifierStart(js.charAt(j)) || js.charAt(j) == '$' || js.charAt(j) == '_')) {
            int k = j;
            while (k < js.length() && (Character.isJavaIdentifierPart(js.charAt(k)) || js.charAt(k) == '$')) k++;
            List<String> fields = fdFields.get(js.substring(j, k));
            if (fields != null) {
                for (String f : fields) h.params.putIfAbsent(f, f);
                return;
            }
        }
        int brace = js.indexOf('{', i);
        if (brace < 0 || brace - i > 60) return;
        String obj = WebpackParser.balanced(js, brace);
        if (obj.isEmpty()) return;
        Map<String, String> fields = EndpointAnalyzer.parseObject(obj);
        String paramsRaw = fields.get("params");
        if (paramsRaw != null && paramsRaw.trim().startsWith("{")) {
            h.params.putAll(parseNested(paramsRaw));
        } else {
            h.params.putAll(fields);
        }
    }

    /** Map of FormData variable name -> appended field names. */
    private static Map<String, List<String>> extractFormData(String js) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        Matcher m = APPEND_FIELD.matcher(js);
        while (m.find()) {
            out.computeIfAbsent(m.group(1), k -> new ArrayList<>()).add(m.group(2));
        }
        return out;
    }

    /** parseObject expects braces already stripped; this handles a value that still has them. */
    private static Map<String, String> parseNested(String withBraces) {
        String s = withBraces.trim();
        if (s.startsWith("{") && s.endsWith("}")) {
            s = s.substring(1, s.length() - 1);
        }
        return EndpointAnalyzer.parseObject(s);
    }

    /** Resolve an instance path against its baseURL (e.g. "/api" + "/user" -> "/api/user"). */
    private static String resolveBase(String base, String path) {
        if (path.startsWith("http") || path.startsWith("//")) return path;
        if (base == null || base.isEmpty()) return path;
        String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        String p = path.startsWith("/") ? path : "/" + path;
        return b + p;
    }

    /** The captured url value from a URL_FIELD matcher (double/single/backtick quote). */
    public static String urlValue(Matcher m) {
        return m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
    }

    /** Extract `${x}` interpolation vars from a template string into params. */
    public static void extractInterp(String raw, Map<String, String> params) {
        Matcher ip = INTERP.matcher(raw);
        while (ip.find()) {
            String v = ip.group(1).trim();
            if (v.matches("[A-Za-z_$][\\w$]*")) params.putIfAbsent(v, v);
        }
    }

    /** Normalize a template string: replace `${x}` with `{}` (and drop a leading `${host}` prefix). */
    public static String normalizeTemplate(String raw) {
        if (raw == null) return "";
        String s = raw.replaceAll("\\$\\{[^}]*\\}", "{}");
        while (s.startsWith("{}")) {
            s = s.substring(2);
            if (s.startsWith("/")) s = s.substring(1);
        }
        return s;
    }

    /** Strip query string and fragment. */
    public static String stripQuery(String s) {
        if (s == null) return "";
        int cut = s.length();
        int q = s.indexOf('?');
        int f = s.indexOf('#');
        if (q >= 0) cut = Math.min(cut, q);
        if (f >= 0) cut = Math.min(cut, f);
        return s.substring(0, cut);
    }

    /** Root domain (last two labels) or the IP itself. */
    public static String rootDomain(String host) {
        if (host == null || host.isEmpty()) return "";
        if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}") || host.contains(":")) return host;
        String[] parts = host.split("\\.");
        if (parts.length <= 2) return host;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    /** True if the path points at a static asset rather than an API endpoint. */
    public static boolean isStaticPath(String path) {
        if (path == null || path.isEmpty()) return true;
        String p = path.toLowerCase();
        if (p.startsWith("data:") || p.startsWith("blob:") || p.startsWith("javascript:")
                || p.startsWith("about:") || p.startsWith("#") || p.contains(" ")) return true;
        if (p.endsWith(".js") || p.endsWith(".css") || p.endsWith(".png") || p.endsWith(".jpg")
                || p.endsWith(".jpeg") || p.endsWith(".gif") || p.endsWith(".svg") || p.endsWith(".ico")
                || p.endsWith(".woff") || p.endsWith(".woff2") || p.endsWith(".ttf") || p.endsWith(".eot")
                || p.endsWith(".map") || p.endsWith(".html") || p.endsWith(".htm") || p.endsWith(".webp")
                || p.endsWith(".mp4") || p.endsWith(".mp3") || p.endsWith(".pdf") || p.endsWith(".wasm")) return true;
        return false;
    }

    /** True if the url uses a non-HTTP scheme (stun:, turn:, data:, ws:, wss:, mailto:, ...). */
    public static boolean isNonHttpScheme(String url) {
        if (url == null || url.isEmpty()) return true;
        if (url.startsWith("http://") || url.startsWith("https://")) return false;
        if (url.startsWith("//") || url.startsWith("/")) return false;
        return url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*");
    }

    /** True if the value is clearly not a URL/path (non-http scheme, format string, sentence, or code fragment). */
    public static boolean isNotUrl(String url) {
        if (isNonHttpScheme(url)) return true;
        if (url.indexOf('%') >= 0 || url.indexOf(' ') >= 0) return true;   // "%s is not a valid %s"
        if (url.indexOf('(') >= 0 || url.indexOf(')') >= 0) return true;   // ",p).F(" code fragment
        char c = url.charAt(0);
        return !(c == '/' || c == '.' || c == '~' || Character.isLetterOrDigit(c));
    }
}
