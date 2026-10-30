package jscollect.core;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The full endpoint-extraction pipeline shared by the Burp plugin and the
 * scenario test runner. Given a map of JS file URL -> body, it runs the
 * structured (webpack/vite) and generic extractors and merges + dedups the
 * results exactly the way the plugin does.
 *
 * Dedup key is per root domain / IP + method + path (NOT global), so the same
 * path on two different hosts stays as two separate rows.
 */
public final class Pipeline {

    private Pipeline() {}

    /** Full pipeline: webpack + esm + generic, merged and deduped. */
    public static List<Endpoint> analyze(Map<String, String> files) {
        List<Endpoint> eps = new ArrayList<>();
        try {
            eps.addAll(EndpointAnalyzer.analyze(files));
        } catch (Throwable ignored) {
        }
        try {
            eps.addAll(EsmEndpointExtractor.extract(files));
        } catch (Throwable ignored) {
        }

        // generic hits, per file
        Map<String, List<GenericEndpointExtractor.Hit>> genByUrl = new LinkedHashMap<>();
        for (Map.Entry<String, String> fe : files.entrySet()) {
            List<GenericEndpointExtractor.Hit> hits;
            try {
                hits = GenericEndpointExtractor.extract(fe.getValue());
            } catch (Throwable ignored) {
                hits = new ArrayList<>();
            }
            genByUrl.put(fe.getKey(), hits);
        }

        return merge(eps, genByUrl);
    }

    /** Merge structured endpoints + generic hits (dedup per root domain + method + path). */
    public static List<Endpoint> merge(List<Endpoint> webpackEps,
                                       Map<String, List<GenericEndpointExtractor.Hit>> genByUrl) {
        List<Endpoint> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Endpoint ep : webpackEps) {
            if (GenericEndpointExtractor.isNotUrl(ep.url)) continue;
            seen.add(keyOf(WebpackParser.hostOf(ep.sourceFile), ep.method, ep.url));
            out.add(ep);
        }
        for (Map.Entry<String, List<GenericEndpointExtractor.Hit>> ge : genByUrl.entrySet()) {
            String fileUrl = ge.getKey();
            String fileHost = WebpackParser.hostOf(fileUrl);
            for (GenericEndpointExtractor.Hit hit : ge.getValue()) {
                String host;
                String path;
                String display;
                String raw = hit.url;
                if (raw.startsWith("http://") || raw.startsWith("https://")) {
                    try {
                        java.net.URI u = java.net.URI.create(raw);
                        host = u.getHost();
                        path = u.getPath();
                        display = (raw.startsWith("https") ? "https://" : "http://")
                                + u.getAuthority() + u.getPath();
                    } catch (Exception e) {
                        continue;
                    }
                } else if (raw.startsWith("ws://") || raw.startsWith("wss://")) {
                    try {
                        java.net.URI u = java.net.URI.create(raw);
                        host = u.getHost();
                        path = u.getPath();
                        display = raw;
                    } catch (Exception e) {
                        continue;
                    }
                } else if (raw.startsWith("//")) {
                    String rest = raw.substring(2);
                    int slash = rest.indexOf('/');
                    host = slash < 0 ? rest : rest.substring(0, slash);
                    path = slash < 0 ? "/" : rest.substring(slash);
                    display = raw;
                } else if (raw.startsWith("/")) {
                    host = fileHost;
                    path = raw;
                    display = raw;
                } else {
                    // relative path without leading slash: "chat/history" -> "/chat/history"
                    host = fileHost;
                    path = "/" + raw;
                    display = "/" + raw;
                }
                path = GenericEndpointExtractor.stripQuery(path);
                if (GenericEndpointExtractor.isStaticPath(path)) continue;
                String key = keyOf(host, hit.method, path);
                if (seen.contains(key)) continue;
                seen.add(key);
                Endpoint ep = new Endpoint(display, hit.method, hit.wrapper, "-", fileUrl);
                ep.defPos = hit.pos;
                ep.headerFields.addAll(hit.headers);
                // Generic params come straight from the config object (definition-level),
                // NOT from a call-site passthrough, so store them as paramFields.
                ep.paramFields.addAll(hit.params.keySet());
                Endpoint.CallSite cs = new Endpoint.CallSite(fileUrl, hit.pos >= 0 ? hit.pos : 0);
                cs.fields.putAll(hit.params);
                ep.callSites.add(cs);
                out.add(ep);
            }
        }
        return out;
    }

    /** The endpoint's dedup/identity key. */
    public static String keyOf(String host, String method, String url) {
        return GenericEndpointExtractor.rootDomain(host) + "|" + method
                + "|" + GenericEndpointExtractor.stripQuery(url);
    }

    /** Find an endpoint by exact url (helper for tests). */
    public static Endpoint findByUrl(List<Endpoint> eps, String url) {
        for (Endpoint ep : eps) {
            if (ep.url.equals(url)) return ep;
        }
        return null;
    }
}
