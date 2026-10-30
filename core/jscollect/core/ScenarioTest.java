package jscollect.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Scenario test over synthetic fixtures (no Burp dependency). Verifies the full
 * analysis pipeline: webpack4/5 chunk maps, structured endpoint extraction
 * (mutual calls + params), and generic axios/fetch/ajax/xhr extraction.
 *
 * Run:
 *   javac -d out jscollect/core/*.java
 *   java  -cp out jscollect.core.ScenarioTest <fixtures-dir>
 */
public final class ScenarioTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        String dir = args.length > 0 ? args[0] : "test/fixtures";

        String main5 = read(dir, "webpack5-main.js");
        String chunk100 = read(dir, "chunk-100.js");
        String chunk200 = read(dir, "chunk-200.js");
        String wp4 = read(dir, "webpack4-main.js");
        String generic = read(dir, "generic.js");
        String html = read(dir, "index.html");
        String vite = read(dir, "vite-bundle.js");
        String viteWrapper = read(dir, "vite-wrapper.js");
        String viteFunc = read(dir, "vite-func.js");
        String viteMerge = read(dir, "vite-merge.js");
        String viteExport = read(dir, "vite-export.js");

        // ---- A. webpack5 chunk map + publicPath ----
        List<ChunkMap> maps5 = WebpackParser.parseChunkMaps(main5);
        check("wp5 map count == 1", maps5.size() == 1);
        ChunkMap cm5 = maps5.isEmpty() ? null : maps5.get(0);
        check("wp5 prefix == js/", cm5 != null && "js/".equals(cm5.prefix));
        check("wp5 entries == 2", cm5 != null && cm5.entries.size() == 2);
        check("wp5 100 -> aaa111", cm5 != null && "aaa111".equals(cm5.entries.get("100")));
        check("wp5 200 -> bbb222", cm5 != null && "bbb222".equals(cm5.entries.get("200")));
        check("wp5 publicPath == /", "/".equals(WebpackParser.parsePublicPath(main5)));

        // ---- B. webpack5 structured endpoints (mutual + cross-file calls) ----
        Map<String, String> files5 = new LinkedHashMap<>();
        files5.put("webpack5-main.js", main5);
        files5.put("chunk-100.js", chunk100);
        files5.put("chunk-200.js", chunk200);
        List<Endpoint> eps5 = EndpointAnalyzer.analyze(files5);

        Endpoint getUser = find(eps5, "/api/user");
        check("getUser found", getUser != null);
        if (getUser != null) {
            check("getUser method GET", "GET".equals(getUser.method));
            check("getUser exportKey getUser", "getUser".equals(getUser.exportKey));
            check("getUser moduleId 1", "1".equals(getUser.moduleId));
            check("getUser callSites == 3", getUser.callSites.size() == 3);
            check("getUser has fields userId+dept", anyCallSite(getUser, "userId") && anyCallSite(getUser, "dept"));
            check("getUser has bare-id fields userId+tag", anyCallSite(getUser, "tag"));
        }

        Endpoint createUser = find(eps5, "/api/user/create");
        check("createUser found", createUser != null);
        if (createUser != null) {
            check("createUser method POST", "POST".equals(createUser.method));
            check("createUser callSites == 1", createUser.callSites.size() == 1);
            check("createUser fields name+email", anyCallSite(createUser, "name") && anyCallSite(createUser, "email"));
        }

        Endpoint listUsers = find(eps5, "/api/users");
        check("listUsers found", listUsers != null);
        if (listUsers != null) {
            check("listUsers method GET", "GET".equals(listUsers.method));
            check("listUsers callSites == 1", listUsers.callSites.size() == 1);
        }

        Endpoint searchUser = find(eps5, "/api/user/search");
        check("searchUser found", searchUser != null);
        if (searchUser != null) {
            check("searchUser def params pageSize+keyword",
                    searchUser.paramFields.contains("pageSize") && searchUser.paramFields.contains("keyword"));
            check("searchUser callSites == 1", searchUser.callSites.size() == 1);
            check("searchUser call-site keyword field", anyCallSite(searchUser, "keyword"));
        }

        // ---- C. webpack4 chunk map ----
        List<ChunkMap> maps4 = WebpackParser.parseChunkMaps(wp4);
        check("wp4 map count == 1", maps4.size() == 1);
        ChunkMap cm4 = maps4.isEmpty() ? null : maps4.get(0);
        check("wp4 prefix == chunk-", cm4 != null && "chunk-".equals(cm4.prefix));
        check("wp4 entries == 2", cm4 != null && cm4.entries.size() == 2);

        // ---- D. webpack4 structured endpoints (CommonJS exports + function form) ----
        Map<String, String> files4 = new LinkedHashMap<>();
        files4.put("webpack4-main.js", wp4);
        List<Endpoint> eps4 = EndpointAnalyzer.analyze(files4);

        Endpoint legacyGet = find(eps4, "/api/legacy/user");
        check("wp4 legacyGet found", legacyGet != null);
        if (legacyGet != null) {
            check("wp4 legacyGet method GET", "GET".equals(legacyGet.method));
            check("wp4 legacyGet callSites == 1", legacyGet.callSites.size() == 1);
            check("wp4 legacyGet fields id+type", anyCallSite(legacyGet, "id") && anyCallSite(legacyGet, "type"));
        }
        Endpoint legacyPost = find(eps4, "/api/legacy/user/create");
        check("wp4 legacyPost found", legacyPost != null);
        if (legacyPost != null) {
            check("wp4 legacyPost method POST", "POST".equals(legacyPost.method));
        }

        // ---- E. generic extraction ----
        List<GenericEndpointExtractor.Hit> hits = GenericEndpointExtractor.extract(generic);
        checkGeneric(hits, "/api/axios/get", "GET", "axios.get", "page", "size");
        checkGeneric(hits, "/api/axios/create", "POST", "axios.post", "name", "age");
        checkGeneric(hits, "/api/axios/update", "PUT", "axios.put", "id");
        checkGeneric(hits, "/api/axios/del/1", "DELETE", "axios.delete");
        checkGeneric(hits, "/api/fetch/get", "GET", "fetch");
        checkGeneric(hits, "/api/fetch/create", "POST", "fetch", "a", "b");
        checkGeneric(hits, "/api/ajax/save", "POST", "ajax", "k");
        checkGeneric(hits, "/api/ajax/get", "GET", "ajax.get");
        checkGeneric(hits, "/api/ajax/post", "POST", "ajax.post", "p");
        checkGeneric(hits, "/api/ajax/json", "GET", "ajax.getjson");
        checkGeneric(hits, "/api/xhr/get", "GET", "xhr");
        checkGeneric(hits, "/api/xhr/put", "PUT", "xhr");
        checkGeneric(hits, "/api/bare/url", "DELETE", "url");
        checkGeneric(hits, "/api/agent/share/product_sales/login", "POST", "url", "from");
        checkGeneric(hits, "/api/user/{}/profile", "GET", "axios.get", "userId");

        // headers captured from config object
        GenericEndpointExtractor.Hit login = findHit(hits, "/api/agent/share/product_sales/login");
        check("generic headers p+Content-Type", login != null
                && login.headers.contains("p") && login.headers.contains("Content-Type"));

        // ---- F. HTML declarations ----
        check("html script src == 1", WebpackParser.extractScriptSrc(html).size() == 1);
        check("html link hrefs == 3", WebpackParser.extractLinkHrefs(html).size() == 3);

        // ---- G. Vite/Rollup (ESM) API-layer extraction ----
        Map<String, String> filesVite = new LinkedHashMap<>();
        filesVite.put("vite-bundle.js", vite);
        List<Endpoint> epsVite = EsmEndpointExtractor.extract(filesVite);
        Endpoint grantAuth = find(epsVite, "/jk/health/grantUserAuthorization");
        check("vite grantUserAuthorization found", grantAuth != null);
        if (grantAuth != null) {
            check("vite grantUserAuthorization method POST", "POST".equals(grantAuth.method));
            check("vite grantUserAuthorization callSites == 2", grantAuth.callSites.size() == 2);
            check("vite grantUserAuthorization params type+bu+permission",
                    anyCallSite(grantAuth, "type") && anyCallSite(grantAuth, "bu") && anyCallSite(grantAuth, "permission"));
        }
        Endpoint viteGet = find(epsVite, "/jk/personal/getUserInfo");
        check("vite getUserInfo method GET", viteGet != null && "GET".equals(viteGet.method));

        // ---- H. Vite method-in-wrapper + generic .post({url,data}) ----
        Map<String, String> filesWrapper = new LinkedHashMap<>();
        filesWrapper.put("vite-wrapper.js", viteWrapper);
        List<Endpoint> epsWrapper = EsmEndpointExtractor.extract(filesWrapper);
        Endpoint resetPwd = find(epsWrapper, "/api/vip-lbs-cas/cas/resetPwd");
        check("wrapper resetPwd found", resetPwd != null);
        if (resetPwd != null) {
            check("wrapper resetPwd method POST", "POST".equals(resetPwd.method));
            check("wrapper resetPwd params oldPwd+newPwd",
                    anyCallSite(resetPwd, "oldPwd") && anyCallSite(resetPwd, "newPwd"));
        }
        // generic extractor should also report it as POST (not GET), without a wrong duplicate GET
        List<GenericEndpointExtractor.Hit> gwrap = GenericEndpointExtractor.extract(viteWrapper);
        GenericEndpointExtractor.Hit greset = findHit(gwrap, "/api/vip-lbs-cas/cas/resetPwd");
        check("generic .post({url,data}) method POST", greset != null && "POST".equals(greset.method));
        long getCount = gwrap.stream()
                .filter(h -> "/api/vip-lbs-cas/cas/resetPwd".equals(h.url) && "GET".equals(h.method)).count();
        check("generic no wrong GET duplicate", getCount == 0);

        // ---- I. Vite function-form API layer ----
        Map<String, String> filesFunc = new LinkedHashMap<>();
        filesFunc.put("vite-func.js", viteFunc);
        List<Endpoint> epsFunc = EsmEndpointExtractor.extract(filesFunc);
        Endpoint updateSettle = find(epsFunc, "/api/vip-lbs-qlfc/toManageQlfc/settle/updateSettleMsg");
        check("func updateSettleMsg found", updateSettle != null);
        if (updateSettle != null) {
            check("func updateSettleMsg method POST", "POST".equals(updateSettle.method));
            check("func updateSettleMsg callSites == 1", updateSettle.callSites.size() == 1);
            check("func updateSettleMsg params settleMsgId+content",
                    anyCallSite(updateSettle, "settleMsgId") && anyCallSite(updateSettle, "content"));
        }
        check("func async-validator format string filtered", find(epsFunc, "%s is not a valid %s") == null);
        Endpoint reg = find(epsFunc, "/api/vip-lbs-cas/cas/register");
        check("func register found", reg != null);
        if (reg != null) {
            check("func register takes no params (dataTarget==null)", reg.dataTarget == null && reg.paramsTarget == null);
        }
        Endpoint agentByPage = find(epsFunc, "/api/agent/queryAgentByPage");
        check("func queryAgentByPage found via action mapping", agentByPage != null);
        if (agentByPage != null) {
            check("func queryAgentByPage params page+size via getServicersList action",
                    anyCallSite(agentByPage, "page") && anyCallSite(agentByPage, "size"));
        }
        Endpoint submit = find(epsFunc, "/api/order/submit");
        check("func multi-hop submit found", submit != null);
        if (submit != null) {
            check("func multi-hop orderId via outer->inner dispatch chain",
                    anyCallSite(submit, "orderId"));
        }

        // ---- J. Vite merge-chain call site (l(l({},a), {}, {fields})) ----
        Map<String, String> filesMerge = new LinkedHashMap<>();
        filesMerge.put("vite-merge.js", viteMerge);
        List<Endpoint> epsMerge = EsmEndpointExtractor.extract(filesMerge);
        Endpoint updStatus = find(epsMerge, "/api/order/updateOrderStatus");
        check("merge updateOrderStatus found", updStatus != null);
        if (updStatus != null) {
            check("merge updateOrderStatus method POST", "POST".equals(updStatus.method));
            check("merge params updateStatus+updatedBy+orderNo",
                    anyCallSite(updStatus, "updateStatus")
                            && anyCallSite(updStatus, "updatedBy")
                            && anyCallSite(updStatus, "orderNo"));
        }

        // ---- K. webpack export-reference action (Object(f["e"])(payload)) ----
        Map<String, String> filesExport = new LinkedHashMap<>();
        filesExport.put("vite-export.js", viteExport);
        List<Endpoint> epsExport = EsmEndpointExtractor.extract(filesExport);
        Endpoint queryCustomers = find(epsExport, "/api/customer/queryCustomers");
        check("export queryCustomers found", queryCustomers != null);
        if (queryCustomers != null) {
            check("export queryCustomers params page+size via queryAgents export-ref action",
                    anyCallSite(queryCustomers, "page") && anyCallSite(queryCustomers, "size"));
        }

        System.out.println();
        System.out.println("---- structured endpoints (wp5) ----");
        for (Endpoint ep : eps5) {
            System.out.println("  " + ep.method + " " + ep.url + " [" + ep.exportKey + " @" + ep.moduleId
                    + "] callSites=" + ep.callSites.size() + " defParams=" + ep.paramFields);
        }
        System.out.println("---- structured endpoints (wp4) ----");
        for (Endpoint ep : eps4) {
            System.out.println("  " + ep.method + " " + ep.url + " [" + ep.exportKey + " @" + ep.moduleId
                    + "] callSites=" + ep.callSites.size());
        }
        System.out.println("---- generic hits ----");
        for (GenericEndpointExtractor.Hit h : hits) {
            System.out.println("  " + h.method + " " + h.url + " [" + h.wrapper + "] params=" + h.params.keySet());
        }
        System.out.println();
        System.out.println("========================================");
        System.out.println("passed " + passed + ", failed " + failed);
        System.out.println("========================================");
        if (failed > 0) System.exit(1);
    }

    private static void checkGeneric(List<GenericEndpointExtractor.Hit> hits, String url,
                                     String method, String wrapper, String... paramKeys) {
        GenericEndpointExtractor.Hit h = findHit(hits, url);
        boolean ok = h != null && method.equals(h.method) && wrapper.equals(h.wrapper);
        for (String k : paramKeys) ok = ok && h != null && h.params.containsKey(k);
        check("generic " + wrapper + " " + method + " " + url + (paramKeys.length == 0 ? "" : " params" + java.util.Arrays.toString(paramKeys)), ok);
        if (h == null) {
            System.out.println("     (missing hit)");
        } else if (!ok) {
            System.out.println("     (actual: " + h.method + " " + h.url + " [" + h.wrapper + "] params=" + h.params.keySet() + ")");
        }
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

    private static boolean anyCallSite(Endpoint ep, String field) {
        for (Endpoint.CallSite cs : ep.callSites) {
            if (cs.fields.containsKey(field)) return true;
        }
        return false;
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

    private static String read(String dir, String name) throws Exception {
        return new String(Files.readAllBytes(Paths.get(dir, name)), StandardCharsets.UTF_8);
    }
}
