package jscollect.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp-independent parsing: webpack4/5 chunk maps, publicPath, sourcemap, and
 * script/preload declarations in HTML.
 *
 * These regexes were validated against this repo's download_chunks.py
 * (webpack5 real site, 14 chunks); this class is their Java port, shared by the
 * Burp plugin and the local self-test.
 */
public final class WebpackParser {

    // webpack5:  n.u = e => "assets/js/" + e + "." + { 50:"hash" }[e] + ".js"
    private static final Pattern WP5_U = Pattern.compile(
        "\\.u\\s*=\\s*\\w+\\s*=>\\s*\"([^\"]*)\"\\s*\\+\\s*\\w+\\s*\\+\\s*\"\\.\"\\s*\\+\\s*\\{(.*?)}\\s*\\[\\w+]\\s*\\+\\s*\"\\.js\"",
        Pattern.DOTALL);

    // webpack4:  n.u = function(e){ return "chunk-" + e + "." + {...}[e] + ".js" }
    private static final Pattern WP4_U = Pattern.compile(
        "\\.u\\s*=\\s*function\\s*\\(\\s*\\w+\\s*\\)\\s*\\{\\s*return\\s*\"([^\"]*)\"\\s*\\+\\s*\\w+\\s*\\+\\s*\"\\.\"\\s*\\+\\s*\\{(.*?)}\\s*\\[\\w+]\\s*\\+\\s*\"\\.js\"",
        Pattern.DOTALL);

    // webpack4 alternative: jsonpScriptSrc form
    private static final Pattern WP4_JSONP = Pattern.compile(
        "jsonpScriptSrc\\s*[=:]\\s*function\\s*\\(\\s*\\w+\\s*\\)\\s*\\{\\s*return\\s*\"([^\"]*)\"\\s*\\+\\s*\\w+\\s*\\+\\s*\"\\.\"\\s*\\+\\s*\\{(.*?)}\\s*\\[\\w+]\\s*\\+\\s*\"\\.js\"",
        Pattern.DOTALL);

    // Entry inside the map:  "id": "hash"   or   id: "hash"
    private static final Pattern ENTRY = Pattern.compile(
        "(?:\"([^\"]+)\"|(\\d+))\\s*:\\s*\"([0-9a-fA-F]{4,16})\"");

    // publicPath:  n.p = "/"   (the variable name varies, so match .p = "...")
    private static final Pattern PUBLIC_PATH = Pattern.compile(
        "\\b\\w\\.p\\s*=\\s*\"([^\"]*)\"");

    private static final Pattern SOURCEMAP = Pattern.compile(
        "//[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s\"']+)");

    private static final Pattern HTML_SCRIPT = Pattern.compile(
        "<script\\s[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    private static final Pattern HTML_LINK = Pattern.compile(
        "<link\\s[^>]*\\brel\\s*=\\s*[\"'](?:preload|prefetch|modulepreload)[\"'][^>]*\\bhref\\s*=\\s*[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE);

    private WebpackParser() {}

    /** Parse all chunk maps in a JS body (webpack5/4, three forms). */
    public static List<ChunkMap> parseChunkMaps(String js) {
        List<ChunkMap> out = new ArrayList<>();
        for (Pattern p : new Pattern[]{WP5_U, WP4_U, WP4_JSONP}) {
            Matcher m = p.matcher(js);
            while (m.find()) {
                Map<String, String> entries = new LinkedHashMap<>();
                Matcher e = ENTRY.matcher(m.group(2));
                while (e.find()) {
                    String id = e.group(1) != null ? e.group(1) : e.group(2);
                    entries.put(id, e.group(3));
                }
                if (!entries.isEmpty()) {
                    out.add(new ChunkMap(m.group(1), entries));
                }
            }
        }
        return out;
    }

    /** Extract the webpack publicPath literal; default "/" when not found. */
    public static String parsePublicPath(String js) {
        Matcher m = PUBLIC_PATH.matcher(js);
        if (m.find()) {
            String p = m.group(1);
            return p.isEmpty() ? "/" : p;
        }
        return "/";
    }

    public static String extractSourceMapUrl(String js) {
        Matcher m = SOURCEMAP.matcher(js);
        return m.find() ? m.group(1).trim() : null;
    }

    public static List<String> extractScriptSrc(String html) {
        return collect(html, HTML_SCRIPT);
    }

    public static List<String> extractLinkHrefs(String html) {
        return collect(html, HTML_LINK);
    }

    private static List<String> collect(String s, Pattern p) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(s);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    public static boolean isJsContentType(String contentType) {
        return contentType != null && contentType.toLowerCase().contains("javascript");
    }

    /**
     * Match the bracket at openIdx ({ ( [) to its partner and return the inner
     * content (outer brackets excluded). Handles strings and escapes; returns ""
     * when no partner is found.
     */
    public static String balanced(String s, int openIdx) {
        if (openIdx < 0 || openIdx >= s.length()) return "";
        char open = s.charAt(openIdx);
        char close = open == '{' ? '}' : open == '(' ? ')' : open == '[' ? ']' : open;
        int depth = 0;
        char quote = 0;
        for (int i = openIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (c == '\\') { i++; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') { quote = c; continue; }
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return s.substring(openIdx + 1, i);
            }
        }
        return "";
    }

    /** Like {@link #balanced(String, int)} but stops after maxLen chars (returns "" if no partner). */
    public static String balanced(String s, int openIdx, int maxLen) {
        if (openIdx < 0 || openIdx >= s.length()) return "";
        char open = s.charAt(openIdx);
        char close = open == '{' ? '}' : open == '(' ? ')' : open == '[' ? ']' : open;
        int depth = 0;
        char quote = 0;
        int end = Math.min(s.length(), openIdx + maxLen);
        for (int i = openIdx; i < end; i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (c == '\\') { i++; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') { quote = c; continue; }
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return s.substring(openIdx + 1, i);
            }
        }
        return "";
    }

    /** Resolve a relative path into an absolute URL. */
    public static String resolve(String base, String path) {
        try {
            return URI.create(base).resolve(path).toString();
        } catch (Exception e) {
            return path;
        }
    }

    /** Directory of a URL (trailing slash included). */
    public static String baseOf(String url) {
        int i = url.lastIndexOf('/');
        return i < 0 ? "" : url.substring(0, i + 1);
    }

    public static String hostOf(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    /** Origin: scheme://host[:port]. */
    public static String originOf(String url) {
        try {
            URI u = URI.create(url);
            String scheme = u.getScheme();
            String auth = u.getAuthority();   // host[:port]
            if (scheme == null || auth == null) return "";
            return scheme + "://" + auth;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Assemble an absolute chunk URL: origin + publicPath + prefix + id + "." + hash + ".js".
     * When publicPath is absolute it is used directly; root-relative ("/x") is prefixed with origin.
     */
    public static String chunkUrl(String origin, String publicPath, String prefix,
                                  String id, String hash) {
        String base;
        if (publicPath.startsWith("http")) {
            base = publicPath;
        } else if (publicPath.startsWith("/")) {
            base = origin + publicPath;
        } else {
            base = origin + "/" + publicPath;
        }
        if (!base.endsWith("/")) base += "/";
        return base + prefix + id + "." + hash + ".js";
    }

    /**
     * Strip a Burp-saved raw response header ("HTTP/1.1 200 OK ...\r\n\r\n<body>").
     * Returns the input unchanged when it is not an HTTP header block.
     */
    public static String stripHttpResponseHeader(String raw) {
        if (raw == null) return null;
        if (raw.startsWith("HTTP/")) {
            int i = raw.indexOf("\r\n\r\n");
            if (i >= 0) return raw.substring(i + 4);
            i = raw.indexOf("\n\n");
            if (i >= 0) return raw.substring(i + 2);
        }
        return raw;
    }
}
