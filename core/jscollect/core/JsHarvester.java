package jscollect.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Collection core (Burp-independent, unit-testable): feed it JS/HTML and it
 * produces entries that are either "captured" or "pending" (derived un-loaded
 * chunks / sourcemaps that still need fetching).
 */
public final class JsHarvester {

    private final Map<String, JsEntry> byUrl = new LinkedHashMap<>();
    private long nextId = 1;

    private long allocateId() {
        return nextId++;
    }

    /** Store a captured JS body; derive pending chunk and sourcemap URLs. */
    public synchronized JsEntry ingestJs(String url, String body, int status, String src) {
        JsEntry e = byUrl.get(url);
        if (e == null) {
            e = new JsEntry(url, src);
            e.id = allocateId();
            byUrl.put(url, e);
        }
        e.status = status;
        e.size = body == null ? 0 : body.length();

        String origin = WebpackParser.originOf(url);
        String publicPath = WebpackParser.parsePublicPath(body);
        for (ChunkMap cm : WebpackParser.parseChunkMaps(body)) {
            e.isWebpack = true;
            for (String id : cm.entries.keySet()) {
                String cu = WebpackParser.chunkUrl(origin, publicPath,
                        cm.prefix, id, cm.entries.get(id));
                discovered(cu, "runtime");
            }
        }
        String map = WebpackParser.extractSourceMapUrl(body);
        if (map != null) {
            e.hasMap = true;
            e.mapUrl = WebpackParser.resolve(url, map);
            discovered(e.mapUrl, "sourcemap");
        }
        return e;
    }

    /** Derive <script src> and <link preload/prefetch> from HTML. */
    public synchronized void ingestHtml(String url, String html) {
        if (html == null) return;
        for (String s : WebpackParser.extractScriptSrc(html)) {
            discovered(WebpackParser.resolve(url, s), "html");
        }
        for (String s : WebpackParser.extractLinkHrefs(html)) {
            discovered(WebpackParser.resolve(url, s), "html");
        }
    }

    private void discovered(String url, String src) {
        if (url == null || !url.toLowerCase().startsWith("http")) return;
        if (byUrl.containsKey(url)) return;
        JsEntry e = new JsEntry(url, src);
        e.id = allocateId();
        e.status = 0;   // pending
        byUrl.put(url, e);
    }

    public synchronized JsEntry get(String url) {
        return byUrl.get(url);
    }

    /**
     * Mark a URL as pending. Used for 304 / empty-body cases where no real
     * content was obtained; pending() then includes it so the active fetch can
     * re-request it unconditionally (200 + body).
     */
    public synchronized JsEntry markPending(String url) {
        JsEntry e = byUrl.get(url);
        if (e == null) {
            e = new JsEntry(url, "proxy");
            e.id = allocateId();
            byUrl.put(url, e);
        }
        e.status = 0;
        return e;
    }

    public synchronized List<JsEntry> entries() {
        return new ArrayList<>(byUrl.values());
    }

    /** Entries not yet fetched (status == 0); the outer layer (Burp) decides to fetch them. */
    public synchronized List<JsEntry> pending() {
        List<JsEntry> out = new ArrayList<>();
        for (JsEntry e : byUrl.values()) {
            if (e.status == 0) out.add(e);
        }
        return out;
    }

    public synchronized int size() {
        return byUrl.size();
    }
}
