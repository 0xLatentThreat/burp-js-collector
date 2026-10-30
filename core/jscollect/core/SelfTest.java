package jscollect.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Local self-test (no Burp dependency). Verifies WebpackParser / JsHarvester /
 * EndpointAnalyzer against real fixtures.
 *
 * Run:
 *   javac -d out jscollect/core/*.java
 *   java  -cp out jscollect.core.SelfTest <workspace-root>
 */
public final class SelfTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        String root = args.length > 0 ? args[0] : ".";
        Path appJs = Paths.get(root, "app.3fadfece.js");
        Path burpSaved = Paths.get(root, "serverres", "5");

        // Known webpack5 map for the real target (from download_chunks.py --list).
        Map<String, String> expect = new LinkedHashMap<>();
        expect.put("50", "71664f55");
        expect.put("64", "bd8655e1");
        expect.put("110", "32096bc2");
        expect.put("132", "b9511742");
        expect.put("212", "756efc48");
        expect.put("243", "9746345e");
        expect.put("309", "7479c4b0");
        expect.put("499", "46c00005");
        expect.put("575", "020238d9");
        expect.put("604", "9e2daa3b");
        expect.put("692", "ea358c1f");
        expect.put("769", "572866cb");
        expect.put("843", "8805605c");
        expect.put("980", "4fca3a96");

        // ---- 1. webpack5 real map ----
        String app = read(appJs);
        List<ChunkMap> maps = WebpackParser.parseChunkMaps(app);
        check("webpack5 map count == 1", maps.size() == 1);
        if (maps.size() == 1) {
            ChunkMap cm = maps.get(0);
            check("webpack5 prefix == assets/js/", "assets/js/".equals(cm.prefix));
            check("webpack5 entry count == 14", cm.entries.size() == 14);
            boolean exact = cm.entries.equals(expect);
            check("webpack5 14 id->hash all match", exact);
            if (!exact) {
                System.out.println("   actual: " + cm.entries);
            }
            check("publicPath == /", "/".equals(WebpackParser.parsePublicPath(app)));
            String u50 = WebpackParser.chunkUrl("https://221.179.19.76", "/",
                    cm.prefix, "50", "71664f55");
            check("chunkUrl(50) == .../assets/js/50.71664f55.js",
                    "https://221.179.19.76/assets/js/50.71664f55.js".equals(u50));
        }

        // ---- 2. webpack4 two forms (synthetic fixtures) ----
        String wp4a = "var r=window.webpackJsonp||[];"
                + "r.u=function(e){return \"chunk-\"+e+\".\"+{"
                + "\"00cc0b02\":\"cec20e27\",100:\"abc123\""
                + "}[e]+\".js\"};";
        List<ChunkMap> m4a = WebpackParser.parseChunkMaps(wp4a);
        check("webpack4 n.u=function -> 1 map", m4a.size() == 1);
        if (m4a.size() == 1) {
            check("webpack4 prefix == chunk-", "chunk-".equals(m4a.get(0).prefix));
            check("webpack4 entries == 2", m4a.get(0).entries.size() == 2);
            check("webpack4 has 00cc0b02->cec20e27",
                    "cec20e27".equals(m4a.get(0).entries.get("00cc0b02")));
        }

        String wp4b = "var t={};t.jsonpScriptSrc=function(e){return \"assets/js/\"+e+\".\"+{"
                + "50:\"71664f55\"}[e]+\".js\"};";
        List<ChunkMap> m4b = WebpackParser.parseChunkMaps(wp4b);
        check("webpack4 jsonpScriptSrc -> 1 map", m4b.size() == 1);

        // ---- 3. sourcemap ----
        String sm = "//# sourceMappingURL=app.3fadfece.js.map\n";
        check("sourcemap extraction", "app.3fadfece.js.map".equals(
                WebpackParser.extractSourceMapUrl(sm)));

        // ---- 4. HTML parsing ----
        String html = "<html><head>"
                + "<script src=\"/js/a.js\"></script>"
                + "<link rel=\"prefetch\" href=\"/js/b.js\">"
                + "<link rel=\"preload\" as=\"script\" href=\"/js/c.js\">"
                + "</head></html>";
        List<String> scripts = WebpackParser.extractScriptSrc(html);
        List<String> links = WebpackParser.extractLinkHrefs(html);
        check("HTML script src extraction", scripts.size() == 1 && "/js/a.js".equals(scripts.get(0)));
        check("HTML link extraction == 2", links.size() == 2);

        // ---- 5. strip Burp HTTP response header ----
        String raw = read(burpSaved);
        String body = WebpackParser.stripHttpResponseHeader(raw);
        check("stripped body no longer starts with HTTP/", body != null && !body.startsWith("HTTP/"));
        check("stripped body starts with use strict or (self",
                body.startsWith("\"use strict\"") || body.startsWith("(self"));

        // ---- 6. Harvester end-to-end ----
        JsHarvester h = new JsHarvester();
        h.ingestJs("https://221.179.19.76/assets/js/app.3fadfece.js", app, 200, "proxy");
        check("harvester total entries == 1 + 14", h.size() == 15);
        check("harvester pending == 14", h.pending().size() == 14);
        JsEntry appEntry = h.get("https://221.179.19.76/assets/js/app.3fadfece.js");
        check("app entry flagged isWebpack", appEntry != null && appEntry.isWebpack);
        check("pending contains 50.71664f55",
                h.get("https://221.179.19.76/assets/js/50.71664f55.js") != null);

        System.out.println();

        // ---- 7. endpoint + param analysis (golden comparison) ----
        Map<String, String> files = new LinkedHashMap<>();
        files.put("app.3fadfece.js", app);
        for (int i = 0; i <= 14; i++) {
            Path p = Paths.get(root, "serverres", Integer.toString(i));
            files.put("serverres/" + i, WebpackParser.stripHttpResponseHeader(read(p)));
        }
        List<Endpoint> eps = EndpointAnalyzer.analyze(files);
        check("endpoint count >= 32", eps.size() >= 32);

        Endpoint salary = find(eps, "/pad-hrms-pdc/api/commission/personalSalary/details");
        check("found personalSalary/details", salary != null);
        if (salary != null) {
            check("  method == POST", "POST".equals(salary.method));
            check("  exportKey == fy", "fy".equals(salary.exportKey));
            check("  moduleId == 5662", "5662".equals(salary.moduleId));
            check("  callSites == 1", salary.callSites.size() == 1);
            if (!salary.callSites.isEmpty()) {
                Endpoint.CallSite cs = salary.callSites.get(0);
                check("  call site from serverres/5", cs.file.contains("serverres/5"));
                check("  fields contain umNum/start/end",
                        cs.fields.containsKey("umNum")
                        && cs.fields.containsKey("start")
                        && cs.fields.containsKey("end"));
            }
        }

        Endpoint role = find(eps, "/pad-hrms-pdc/api/commission/personalSalary/getRoleByUm");
        check("found getRoleByUm", role != null);
        if (role != null) {
            check("  getRoleByUm exportKey == QN", "QN".equals(role.exportKey));
            check("  getRoleByUm callSites == 2", role.callSites.size() == 2);
        }

        // ---- 8. generic endpoint extraction (synthetic fixtures) ----
        String g = "axios.get('/api/a', {params:{p:1,q:2}});"
                + "fetch('/api/b');"
                + "$.ajax({url:'/api/c', type:'POST', data:{x:1}});"
                + "var x=new XMLHttpRequest(); x.open('GET','/api/d');"
                + "var c={url:'/api/e', method:'PUT'};";
        List<GenericEndpointExtractor.Hit> hits = GenericEndpointExtractor.extract(g);
        check("generic: at least 5 hits", hits.size() >= 5);
        GenericEndpointExtractor.Hit ax = findHit(hits, "/api/a");
        check("generic: axios.get /api/a found", ax != null);
        if (ax != null) {
            check("generic: axios method == GET", "GET".equals(ax.method));
            check("generic: axios params p,q", ax.params.containsKey("p") && ax.params.containsKey("q"));
        }
        GenericEndpointExtractor.Hit aj = findHit(hits, "/api/c");
        check("generic: ajax /api/c method == POST", aj != null && "POST".equals(aj.method));
        check("generic: ajax param x", aj != null && aj.params.containsKey("x"));

        check("rootDomain: a.b.example.com == example.com",
                "example.com".equals(GenericEndpointExtractor.rootDomain("a.b.example.com")));
        check("rootDomain: IP kept", "221.179.19.76".equals(
                GenericEndpointExtractor.rootDomain("221.179.19.76")));
        check("isStaticPath: /a.js == true", GenericEndpointExtractor.isStaticPath("/a.js"));
        check("isStaticPath: /api/x == false", !GenericEndpointExtractor.isStaticPath("/api/x"));
        check("isNonHttpScheme: stun: == true", GenericEndpointExtractor.isNonHttpScheme("stun:webcs.agora.io:3478"));
        check("isNonHttpScheme: /api/x == false", !GenericEndpointExtractor.isNonHttpScheme("/api/x"));
        check("isNonHttpScheme: https == false", !GenericEndpointExtractor.isNonHttpScheme("https://x/y"));
        check("isNotUrl: %s is not a valid %s == true", GenericEndpointExtractor.isNotUrl("%s is not a valid %s"));
        check("isNotUrl: /api/x == false", !GenericEndpointExtractor.isNotUrl("/api/x"));
        check("isNotUrl: ,p).F( == true", GenericEndpointExtractor.isNotUrl(",p).F("));
        check("isNotUrl: chat/history == false", !GenericEndpointExtractor.isNotUrl("chat/history"));

        Map<String, String> seqExp = ModuleParser.exports("r.d(t,\"e\",(function(){return q})),r.d(t,\"a\",(function(){return u}));");
        check("seq export e->q", "e".equals(seqExp.get("q")));
        check("seq export a->u", "a".equals(seqExp.get("u")));
        Map<String, String> imp = ModuleParser.imports("var f=r(\"9671\"),i=r(\"f121\");");
        check("import f->9671", "9671".equals(imp.get("f")));
        check("import i->f121", "f121".equals(imp.get("i")));

        // ---- 9. RiskScanner passive rules (synthetic fixtures) ----
        List<RiskScanner.Finding> rs = RiskScanner.scanResponse(
                "user={\"password\":\"secret123\"} email=a@b.com phone=13800138000",
                null);
        check("risk: secret found", hasKind(rs, "SECRET"));
        check("risk: pii found", hasKind(rs, "PII"));

        List<RiskScanner.Finding> fakeAws = RiskScanner.scanResponse("AKIAAACiCAMAAAD1LOYp", null);
        check("risk: mixed-case AKIA not flagged", !hasKind(fakeAws, "SECRET"));
        List<RiskScanner.Finding> realAws = RiskScanner.scanResponse("AKIA1234567890ABCDEF", null);
        check("risk: uppercase AKIA flagged", hasKind(realAws, "SECRET"));

        List<RiskScanner.Finding> deserRs = RiskScanner.scanResponse(
                "", new byte[]{(byte) 0xac, (byte) 0xed, 0x00, 0x05});
        check("risk: java deser magic", hasKind(deserRs, "DESER"));

        check("risk: sql error detected",
                RiskScanner.containsSqlError("... You have an error in your SQL syntax near '' ..."));
        check("risk: no sql error in clean body",
                !RiskScanner.containsSqlError("{\"code\":0,\"message\":\"ok\"}"));

        check("risk: id-like param umNum", RiskScanner.isIdLikeParam("umNum"));
        check("risk: id-like param agentId", RiskScanner.isIdLikeParam("agentId"));
        check("risk: grid NOT id-like", !RiskScanner.isIdLikeParam("grid"));

        System.out.println();
        System.out.println("---- endpoint list (first entries) ----");
        for (Endpoint ep : eps) {
            System.out.println("  " + ep.method + " " + ep.url + "  [" + ep.exportKey + "]");
        }
        System.out.println();
        System.out.println("========================================");
        System.out.println("passed " + passed + ", failed " + failed);
        System.out.println("========================================");
        if (failed > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  [PASS] " + name);
        } else {
            failed++;
            System.out.println("  [FAIL] " + name);
        }
    }

    private static Endpoint find(List<Endpoint> eps, String url) {
        for (Endpoint ep : eps) {
            if (url.equals(ep.url)) return ep;
        }
        return null;
    }

    private static GenericEndpointExtractor.Hit findHit(List<GenericEndpointExtractor.Hit> hits, String url) {
        for (GenericEndpointExtractor.Hit h : hits) {
            if (url.equals(h.url)) return h;
        }
        return null;
    }

    private static boolean hasKind(List<RiskScanner.Finding> fs, String kind) {
        for (RiskScanner.Finding f : fs) {
            if (kind.equals(f.kind)) return true;
        }
        return false;
    }

    private static String read(Path p) throws Exception {
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }
}
