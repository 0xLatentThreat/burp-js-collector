package burp.jscollect;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jscollect.core.Endpoint;
import jscollect.core.EndpointAnalyzer;
import jscollect.core.EsmEndpointExtractor;
import jscollect.core.GenericEndpointExtractor;
import jscollect.core.JsEntry;
import jscollect.core.JsHarvester;
import jscollect.core.Pipeline;
import jscollect.core.RiskScanner;
import jscollect.core.WebpackParser;

/**
 * JS Collector - a Burp Suite extension (Montoya API).
 *
 * Collects every JavaScript file that flows through the proxy, derives and
 * actively fetches lazy-loaded chunks that the browser never requested
 * (webpack4/5 runtime chunk map + sourcemaps + HTML preload declarations),
 * then statically extracts the API endpoints and their request parameter
 * fields from the collected code.
 *
 * UI: a single "JS Collector" suite tab with two sub-tabs (JS / Endpoints).
 * Fully automatic - no buttons to click. The only control is the
 * "Auto-fetch discovered" checkbox (enabled by default).
 */
public class BurpJsCollector implements BurpExtension {

    private MontoyaApi api;
    private final JsHarvester harvester = new JsHarvester();
    private final Map<String, String> bodies = new ConcurrentHashMap<>();
    private final Map<String, String> cookiePool = new ConcurrentHashMap<>();
    private String baseOrigin = "";

    private static final int MAX_JS_SIZE = 5 * 1024 * 1024; // 5MB limit
    private volatile boolean onlyInScope = false;
    private volatile boolean autoFetch = true;
    private volatile boolean fetchRunning = false;
    private final Map<String, HttpRequest> reqStore = new ConcurrentHashMap<>();
    private final Map<String, HttpResponse> respStore = new ConcurrentHashMap<>();

    // Background workers: heavy work (harvest / fetch / analyze) NEVER runs on
    // the proxy thread or the Swing EDT, so Burp stays responsive.
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> analyzeTask;
    private final Map<String, Long> endpointIds = new ConcurrentHashMap<>();
    private long nextEndpointId = 1;
    private final Map<String, Integer> probeStatus = new ConcurrentHashMap<>();
    private final Map<String, HttpRequest> epReqStore = new ConcurrentHashMap<>();
    private final Map<String, HttpResponse> epRespStore = new ConcurrentHashMap<>();
    private final Map<String, List<RiskScanner.Finding>> findingsByEndpoint = new ConcurrentHashMap<>();
    private final Map<String, FindingRecord> findingRecords = new ConcurrentHashMap<>();
    // Incremental analysis cache (per-file; only changed files are re-extracted).
    private final Map<String, Integer> bodyHashCache = new ConcurrentHashMap<>();
    private final Map<String, List<Endpoint>> wpDefsCache = new ConcurrentHashMap<>();
    private final Map<String, List<Endpoint>> esmDefsCache = new ConcurrentHashMap<>();
    private final Map<String, List<GenericEndpointExtractor.Hit>> genHitsCache = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong nextFindingId = new java.util.concurrent.atomic.AtomicLong(1);
    private FindingsTableModel findingsModel;
    private JTable findingsTable;
    private JTable epTable;
    private volatile long streamGen = 0;

    private JsTableModel jsModel;
    private EndpointTableModel epModel;
    private JLabel statusLabel;
    private JTable jsTable;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        // Force JOptionPane buttons to English regardless of the JVM/system locale
        // (otherwise a Chinese-locale Burp JRE shows "确定"/"取消" in our dialogs).
        UIManager.put("OptionPane.okButtonText", "OK");
        UIManager.put("OptionPane.cancelButtonText", "Cancel");
        UIManager.put("OptionPane.yesButtonText", "Yes");
        UIManager.put("OptionPane.noButtonText", "No");
        api.extension().setName("JS Collector");
        api.userInterface().registerSuiteTab("JS Collector", buildMainTab());
        api.proxy().registerResponseHandler(new JsResponseHandler());
        api.extension().registerUnloadingHandler(this::onUnload);
        api.logging().logToOutput("[JSCollector] loaded (Montoya)");
    }

    private void onUnload() {
        try {
            autoSave();
        } catch (Exception ignored) {}
        try {
            worker.shutdownNow();
            scheduler.shutdownNow();
        } catch (Exception ignored) {}
        api.logging().logToOutput("[JSCollector] unloaded");
    }

    // ==================================================================
    // Collection
    // ==================================================================
    private class JsResponseHandler implements ProxyResponseHandler {
        @Override
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse r) {
            try {
                // Do only cheap, synchronous work here (extract strings + snapshot),
                // then hand the heavy parsing off to the background worker so the
                // proxy thread returns immediately and Burp never freezes.
                String url = r.initiatingRequest().url();
                if (onlyInScope && !api.scope().isInScope(url)) {
                    return ProxyResponseReceivedAction.continueWith(r);
                }
                rememberContext(r.initiatingRequest());
                String ctype = contentTypeOf(r);
                boolean isJs = url.toLowerCase().endsWith(".js")
                        || url.toLowerCase().contains(".js?")
                        || WebpackParser.isJsContentType(ctype);
                if (isJs) {
                    String body = r.bodyToString();
                    short sc = r.statusCode();
                    HttpRequest req = r.initiatingRequest();
                    HttpResponse resp = r;
                    worker.execute(() -> handleJs(url, body, sc, req, resp));
                } else if (ctype.contains("text/html")) {
                    String html = r.bodyToString();
                    worker.execute(() -> handleHtml(url, html));
                }
            } catch (Exception e) {
                api.logging().logToError(e);
            }
            return ProxyResponseReceivedAction.continueWith(r);
        }

        @Override
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse r) {
            return ProxyResponseToBeSentAction.continueWith(r);
        }
    }

    private void handleJs(String url, String body, short sc, HttpRequest req, HttpResponse resp) {
        try {
            if (sc == 304 || body == null || body.isEmpty()) {
                // 304 = cache hit (no body). Mark as pending; the active fetch will
                // re-request it unconditionally to get a 200 body.
                harvester.markPending(url);
            } else {
                if (body.length() > MAX_JS_SIZE) {
                    api.logging().logToOutput("[JSCollector] Skipping oversized JS (" + (body.length() / 1024) + " KB > 5MB): " + url);
                    return;
                }
                // Put the body FIRST so the analyzer always sees it, even if the
                // (heavier) ingest step below throws on a malformed file.
                bodies.put(url, body);
                reqStore.put(url, req);
                respStore.put(url, resp);
                try {
                    harvester.ingestJs(url, body, sc, "proxy");
                } catch (Exception ex) {
                    api.logging().logToError("[JSCollector] ingest failed " + url + " : " + ex);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[JSCollector] handleJs failed " + url + " : " + e);
        } finally {
            if (jsModel != null) SwingUtilities.invokeLater(jsModel::refresh);
            scheduleAnalyze();
            maybeAutoFetch();
        }
    }

    private void handleHtml(String url, String html) {
        try {
            harvester.ingestHtml(url, html);
        } catch (Exception e) {
            api.logging().logToError("[JSCollector] handleHtml failed " + url + " : " + e);
        } finally {
            if (jsModel != null) SwingUtilities.invokeLater(jsModel::refresh);
            scheduleAnalyze();
            maybeAutoFetch();
        }
    }

    private String contentTypeOf(HttpResponse resp) {
        for (HttpHeader h : resp.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) return h.value().toLowerCase();
        }
        return "";
    }

    private void rememberContext(HttpRequest req) {
        String host = WebpackParser.hostOf(req.url());
        if (baseOrigin.isEmpty()) baseOrigin = WebpackParser.originOf(req.url());
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase("Cookie")) cookiePool.put(host, h.value());
        }
    }

    // ==================================================================
    // Active fetch (replaces the "preload rewrite" trick - fetch ourselves)
    // ==================================================================
    private void maybeAutoFetch() {
        if (autoFetch && !fetchRunning && !harvester.pending().isEmpty()) {
            fetchPending();
        }
    }

    private void fetchPending() {
        if (fetchRunning) return;
        fetchRunning = true;
        new Thread(() -> {
            Set<String> fetched = new HashSet<>();
            try {
                // Loop until no un-fetched pending chunks remain. Ingesting a chunk can
                // discover MORE nested chunks (multi-level lazy loading); re-scan until quiet.
                while (true) {
                    List<JsEntry> pending = new ArrayList<>(harvester.pending());
                    pending.removeIf(e -> fetched.contains(e.url));
                    if (pending.isEmpty()) break;
                    for (JsEntry e : pending) {
                        fetched.add(e.url);
                        if (onlyInScope && !api.scope().isInScope(e.url)) {
                            continue;
                        }
                        try {
                            String host = e.host;
                            List<HttpHeader> headers = new ArrayList<>();
                            headers.add(HttpHeader.httpHeader("User-Agent", "Mozilla/5.0"));
                            headers.add(HttpHeader.httpHeader("Accept", "*/*"));
                            if (cookiePool.containsKey(host)) {
                                headers.add(HttpHeader.httpHeader("Cookie", cookiePool.get(host)));
                            }
                            java.net.URI u = java.net.URI.create(e.url);
                            int port = u.getPort() == -1
                                    ? (e.url.startsWith("https") ? 443 : 80) : u.getPort();
                            HttpRequest req = HttpRequest.httpRequestFromUrl(e.url)
                                    .withService(HttpService.httpService(u.getHost(), port,
                                            e.url.startsWith("https")))
                                    .withAddedHeaders(headers.toArray(new HttpHeader[0]));
                            HttpRequestResponse rr = api.http().sendRequest(req);
                            HttpResponse resp = rr.response();
                            String body = resp.bodyToString();
                            if (body != null && body.length() > MAX_JS_SIZE) {
                                api.logging().logToOutput("[JSCollector] Skipping oversized chunk (" + (body.length() / 1024) + " KB > 5MB): " + e.url);
                                continue;
                            }
                            harvester.ingestJs(e.url, body, resp.statusCode(), "runtime");
                            bodies.put(e.url, body);
                            reqStore.put(e.url, req);
                            respStore.put(e.url, resp);
                        } catch (Exception ex) {
                            api.logging().logToError("fetch failed " + e.url + " : " + ex);
                        }
                    }
                }
            } finally {
                fetchRunning = false;
            }
            SwingUtilities.invokeLater(jsModel::refresh);
            scheduleAnalyze();
        }).start();
    }

    // ==================================================================
    // Endpoint analysis (debounced, off the EDT)
    // ==================================================================
    private void scheduleAnalyze() {
        synchronized (this) {
            if (analyzeTask != null) analyzeTask.cancel(false);
            analyzeTask = scheduler.schedule(this::runAnalyze, 400, TimeUnit.MILLISECONDS);
        }
    }

    private void runAnalyze() {
        try {
            // Incremental: only re-extract changed/new files; reuse cached definitions.
            List<Endpoint> wpDefs = new ArrayList<>();
            List<Endpoint> esmDefs = new ArrayList<>();
            Map<String, List<GenericEndpointExtractor.Hit>> genHitsByUrl = new LinkedHashMap<>();

            for (Map.Entry<String, String> be : bodies.entrySet()) {
                String url = be.getKey();
                String body = be.getValue();
                int h = body == null ? 0 : body.hashCode();
                Integer prev = bodyHashCache.put(url, h);
                boolean changed = prev == null || prev.intValue() != h;

                List<Endpoint> wd = wpDefsCache.get(url);
                if (changed || wd == null) {
                    try { wd = EndpointAnalyzer.extractDefinitionsFrom(url, body); }
                    catch (Throwable t) { api.logging().logToError("[JSCollector] wp defs failed " + url, t); wd = new ArrayList<>(); }
                    wpDefsCache.put(url, wd);
                }
                wpDefs.addAll(wd);

                List<Endpoint> ed = esmDefsCache.get(url);
                if (changed || ed == null) {
                    try { ed = EsmEndpointExtractor.extractDefinitionsFrom(url, body); }
                    catch (Throwable t) { api.logging().logToError("[JSCollector] esm defs failed " + url, t); ed = new ArrayList<>(); }
                    esmDefsCache.put(url, ed);
                }
                esmDefs.addAll(ed);

                List<GenericEndpointExtractor.Hit> gh = genHitsCache.get(url);
                if (changed || gh == null) {
                    try { gh = GenericEndpointExtractor.extract(body); }
                    catch (Throwable t) { api.logging().logToError("[JSCollector] generic failed " + url, t); gh = new ArrayList<>(); }
                    genHitsCache.put(url, gh);
                }
                genHitsByUrl.put(url, gh);
            }

            // Cross-file call-site matching (cheaper than definition extraction).
            List<Endpoint> eps = new ArrayList<>();
            try {
                eps.addAll(EndpointAnalyzer.matchCallSites(wpDefs, bodies));
            } catch (Throwable t) {
                api.logging().logToError("[JSCollector] webpack analyze failed", t);
            }
            try {
                eps.addAll(EsmEndpointExtractor.matchCallSites(esmDefs, bodies));
            } catch (Throwable t) {
                api.logging().logToError("[JSCollector] esm analyze failed", t);
            }

            List<Endpoint> merged = mergedOrFallback(eps, genHitsByUrl);
            // Assign stable, monotonic ids (new endpoints append at the bottom).
            synchronized (endpointIds) {
                for (Endpoint ep : merged) {
                    Long id = endpointIds.get(ep.url);
                    if (id == null) {
                        id = nextEndpointId++;
                        endpointIds.put(ep.url, id);
                    }
                    ep.id = id;
                }
            }
            merged.sort((a, b) -> Long.compare(a.id, b.id));
            for (Endpoint ep : merged) {
                String body = ep.sourceFile != null ? bodies.get(ep.sourceFile) : null;
                ep.defSnippet = body != null && ep.defPos >= 0 ? snippetAround(body, ep.defPos) : "";
            }
            addIdorFindings(merged);
            scanJsBodiesForFindings(merged);
            api.logging().logToOutput("[JSCollector] analyzed " + merged.size() + " endpoints (webpack + generic) from "
                    + bodies.size() + " JS bodies");
            streamEndpoints(merged);
        } catch (Throwable e) {
            // Surface the failure instead of silently dropping it on this background thread.
            api.logging().logToError("[JSCollector] analyze failed", e);
        }
    }

    /** Stream endpoints into the table one-by-one for a progressive (live) look. */
    private void streamEndpoints(List<Endpoint> eps) {
        final long gen = ++streamGen;
        SwingUtilities.invokeLater(() -> {
            if (gen == streamGen && epModel != null) epModel.set(new ArrayList<>());
        });
        new Thread(() -> {
            for (Endpoint ep : eps) {
                SwingUtilities.invokeLater(() -> {
                    if (gen == streamGen && epModel != null) {
                        epModel.append(ep);
                        refreshStatus();
                    }
                });
                try {
                    Thread.sleep(20);
                } catch (InterruptedException ignored) {
                }
            }
        }).start();
    }

    /**
     * Merge webpack (structured) endpoints with generic (directly-written) ones.
     * Dedupe is per root domain / IP + method + path (NOT global), so the same
     * path on two different hosts stays as two separate rows.
     */
    private List<Endpoint> mergedOrFallback(List<Endpoint> eps, Map<String, List<GenericEndpointExtractor.Hit>> genHitsByUrl) {
        try {
            return mergeGeneric(eps, genHitsByUrl);
        } catch (Throwable t) {
            api.logging().logToError("[JSCollector] generic merge failed", t);
            return new ArrayList<>(eps);   // keep webpack/esm endpoints even if generic extraction broke
        }
    }

    private List<Endpoint> mergeGeneric(List<Endpoint> webpackEps,
                                        Map<String, List<GenericEndpointExtractor.Hit>> genHitsByUrl) {
        return Pipeline.merge(webpackEps, genHitsByUrl);
    }

    private static String keyOf(String host, String method, String url) {
        return GenericEndpointExtractor.rootDomain(host) + "|" + method
                + "|" + GenericEndpointExtractor.stripQuery(url);
    }

    private void refreshStatus() {
        if (statusLabel != null && epModel != null) {
            statusLabel.setText(harvester.size() + " JS  ·  " + epModel.rows.size() + " endpoints");
        }
    }

    // ==================================================================
    // UI: single window, two sub-tabs
    // ==================================================================
    private Component buildMainTab() {
        jsModel = new JsTableModel(harvester);
        jsTable = new JTable(jsModel);
        jsTable.setAutoCreateRowSorter(true);
        jsTable.getColumnModel().getColumn(0).setMaxWidth(50);

        JPopupMenu jsPopup = new JPopupMenu();
        jsPopup.add(menuItem("Send to Repeater", () ->
                api.repeater().sendToRepeater(HttpRequest.httpRequestFromUrl(selectedJs().url),
                        "js:" + selectedJs().url)));
        jsPopup.add(menuItem("Preview (Request + Response)", () -> preview(selectedJs())));
        jsPopup.add(menuItem("Export Body to File", () -> exportBody(selectedJs())));
        jsPopup.add(menuItem("Copy URL", () -> copyText(selectedJs().url)));
        jsTable.addMouseListener(popupListener(jsTable, jsPopup));
        jsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int r = jsTable.rowAtPoint(e.getPoint());
                    if (r >= 0) preview(jsModel.row(jsTable.convertRowIndexToModel(r)));
                }
            }
        });

        epModel = new EndpointTableModel(probeStatus, findingsByEndpoint);
        epTable = new JTable(epModel) {
            @Override
            public String getToolTipText(java.awt.event.MouseEvent e) {
                int r = rowAtPoint(e.getPoint());
                int c = columnAtPoint(e.getPoint());
                if (r >= 0 && c == 6) {   // Source column -> full multi-line snippet
                    Endpoint ep = epModel.row(convertRowIndexToModel(r));
                    if (ep != null && ep.defPos >= 0) {
                        String body = ep.sourceFile != null ? bodies.get(ep.sourceFile) : null;
                        if (body != null) {
                            return "<html><pre>" + escapeHtml(snippetMultiLine(body, ep.defPos)) + "</pre></html>";
                        }
                    }
                }
                return super.getToolTipText(e);
            }
        };
        epTable.setAutoCreateRowSorter(true);
        epTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        epTable.setDefaultRenderer(Object.class, new RiskCellRenderer());
        JPopupMenu epPopup = new JPopupMenu();
        epPopup.add(menuItem("Send selected to Repeater", () -> {
            for (int vr : epTable.getSelectedRows()) {
                Endpoint ep = epModel.row(epTable.convertRowIndexToModel(vr));
                api.repeater().sendToRepeater(endpointRequest(ep), ep.method + " " + ep.url);
            }
        }));
        epPopup.add(menuItem("Preview (Request + Response)", () -> {
            int vr = epTable.getSelectionModel().getLeadSelectionIndex();
            if (vr >= 0) previewEndpoint(epModel.row(epTable.convertRowIndexToModel(vr)));
        }));
        epPopup.add(menuItem("View source JS", () -> {
            int vr = epTable.getSelectionModel().getLeadSelectionIndex();
            if (vr >= 0) viewJsSource(epModel.row(epTable.convertRowIndexToModel(vr)));
        }));
        epTable.addMouseListener(popupListener(epTable, epPopup));
        epTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int r = epTable.rowAtPoint(e.getPoint());
                    if (r >= 0) previewEndpoint(epModel.row(epTable.convertRowIndexToModel(r)));
                }
            }
        });

        // Endpoints sub-tab: probe connectivity + export buttons
        JButton probe = new JButton("Probe alive");
        probe.addActionListener(e -> probeAll());
        JButton export = new JButton("Export report");
        export.addActionListener(e -> exportReport());
        JPanel epTop = new JPanel(new FlowLayout(FlowLayout.LEFT));
        epTop.add(probe);
        epTop.add(export);
        epTop.add(hint("Endpoints extracted from collected JS. Right-click: Send selected to Repeater / Preview. Double-click: preview request + response."));
        JPanel epPanel = new JPanel(new BorderLayout());
        epPanel.add(epTop, BorderLayout.NORTH);
        epPanel.add(new JScrollPane(epTable), BorderLayout.CENTER);

        JPanel jsPanel = new JPanel(new BorderLayout());
        jsPanel.add(hint("All JavaScript collected from proxy traffic, lazy-loaded chunks, sourcemaps and HTML preload/script. Double-click or right-click a row to preview / export."),
                BorderLayout.NORTH);
        jsPanel.add(new JScrollPane(jsTable), BorderLayout.CENTER);

        findingsModel = new FindingsTableModel();
        findingsTable = new JTable(findingsModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setDefaultRenderer(Object.class, new FindingsCellRenderer());
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int r = findingsTable.rowAtPoint(e.getPoint());
                    if (r >= 0) openFindingsDetail(findingsModel.row(findingsTable.convertRowIndexToModel(r)));
                }
            }
        });
        JPanel findingsPage = new JPanel(new BorderLayout());
        findingsPage.add(hint("Risk findings from passive security rules (secrets, PII, internal info, serialization magic, IDOR hints). Double-click a row to inspect evidence."),
                BorderLayout.NORTH);
        findingsPage.add(new JScrollPane(findingsTable), BorderLayout.CENTER);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("JS", jsPanel);
        tabs.addTab("Endpoints", epPanel);
        tabs.addTab("Findings", findingsPage);

        JCheckBox scopeOnly = new JCheckBox("Only in-scope", onlyInScope);
        scopeOnly.setToolTipText("Only process JS and extract endpoints for targets in Burp's Target Scope");
        scopeOnly.addActionListener(e -> onlyInScope = scopeOnly.isSelected());

        JCheckBox auto = new JCheckBox("Auto-fetch discovered", true);
        auto.setToolTipText("Automatically fetch lazy-loaded chunks discovered via runtime maps");
        auto.addActionListener(e -> {
            autoFetch = auto.isSelected();
            if (autoFetch) maybeAutoFetch();
        });
        statusLabel = new JLabel("0 JS  ·  0 endpoints");

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        top.add(scopeOnly);
        top.add(auto);
        top.add(statusLabel);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(top, BorderLayout.NORTH);
        panel.add(tabs, BorderLayout.CENTER);
        return panel;
    }

    private JMenuItem menuItem(String title, Runnable action) {
        JMenuItem mi = new JMenuItem(title);
        mi.addActionListener(e -> action.run());
        return mi;
    }

    private JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(Color.GRAY);
        l.setFont(l.getFont().deriveFont(11f));
        return l;
    }

    private MouseAdapter popupListener(JTable table, JPopupMenu popup) {
        return new MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) { maybe(e); }
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) { maybe(e); }
            private void maybe(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = table.rowAtPoint(e.getPoint());
                    if (r >= 0 && !table.isRowSelected(r)) {
                        // Only reset selection when clicking an unselected row, so
                        // multi-select is preserved for batch "send to Repeater".
                        table.setRowSelectionInterval(r, r);
                    }
                    popup.show(table, e.getX(), e.getY());
                }
            }
        };
    }

    private JsEntry selectedJs() {
        return jsModel.row(jsTable.convertRowIndexToModel(jsTable.getSelectedRow()));
    }

    private void copyText(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(s), null);
    }

    // ==================================================================
    // Preview / export / build endpoint request
    // ==================================================================
    private void preview(JsEntry e) {
        HttpRequest req = reqStore.get(e.url);
        if (req == null) req = HttpRequest.httpRequestFromUrl(e.url);
        showMessageView(e.url, req, respStore.get(e.url));
    }

    /** Show an endpoint's probe request + response (double-click / right-click). */
    private void previewEndpoint(Endpoint ep) {
        String key = epKey(ep);
        HttpRequest req = epReqStore.get(key);
        if (req == null) req = endpointRequest(ep);
        showMessageView(ep.method + " " + ep.url, req, epRespStore.get(key));
    }

    /** Open the source JS in Burp's native request/response viewer (same as the JS tab). */
    private void viewJsSource(Endpoint ep) {
        String url = ep.sourceFile;
        HttpRequest req = reqStore.get(url);
        if (req == null) req = HttpRequest.httpRequestFromUrl(url);
        showMessageView(url, req, respStore.get(url));
    }

    /** Open a finding's detail: summary + request + response. */
    private void openFindingsDetail(FindingRecord rec) {
        HttpRequest req = rec.request;
        if (req == null) req = HttpRequest.httpRequestFromUrl(
                rec.url.startsWith("http") ? rec.url : baseOrigin + rec.url);
        HttpResponse resp = rec.response;

        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor();
        if (req != null) reqEditor.setRequest(req);
        if (resp != null) respEditor.setResponse(resp);

        JTextArea summary = new JTextArea(rec.summary());
        summary.setEditable(false);
        summary.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                reqEditor.uiComponent(), respEditor.uiComponent());
        split.setResizeWeight(0.5);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(summary), BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);

        JFrame frame = new JFrame(rec.finding.severity + " " + rec.finding.kind + " - " + rec.url);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setContentPane(panel);
        frame.setSize(960, 720);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void showMessageView(String title, HttpRequest req, HttpResponse resp) {
        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor();
        reqEditor.setRequest(req);
        if (resp != null) respEditor.setResponse(resp);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                reqEditor.uiComponent(), respEditor.uiComponent());
        split.setResizeWeight(0.5);

        JFrame frame = new JFrame(title);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setContentPane(split);
        frame.setSize(1200, 720);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void exportBody(JsEntry e) {
        JFileChooser fc = new JFileChooser();
        String name = e.url.substring(e.url.lastIndexOf('/') + 1);
        if (name.isEmpty()) name = "export.js";
        fc.setSelectedFile(new java.io.File(name));
        if (fc.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.write(fc.getSelectedFile().toPath(),
                        bodies.getOrDefault(e.url, "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                api.logging().logToOutput("[JSCollector] exported " + fc.getSelectedFile());
            } catch (Exception ex) {
                api.logging().logToError(ex);
            }
        }
    }

    private HttpRequest endpointRequest(Endpoint ep) {
        String full = joinUrl(originFor(ep), ep.url);
        HttpRequest req = HttpRequest.httpRequestFromUrl(full).withMethod(ep.method);
        boolean hasBody = "POST".equalsIgnoreCase(ep.method)
                || "PUT".equalsIgnoreCase(ep.method)
                || "PATCH".equalsIgnoreCase(ep.method);
        if (hasBody) {
            Set<String> fields = allFieldNames(ep);
            StringBuilder sb = new StringBuilder("{");
            int i = 0;
            for (String k : fields) {
                if (i++ > 0) sb.append(',');
                sb.append('"').append(k).append("\":\"\"");
            }
            sb.append('}');
            req = req.withHeader("Content-Type", "application/json").withBody(sb.toString());
        }
        return req;
    }

    /**
     * The correct origin for an endpoint is the origin of the JS file it was
     * extracted from (ep.sourceFile is the URL of that file), NOT a single
     * global "first seen host" (baseOrigin). This fixes relative endpoints being
     * sent to the wrong host when multiple sites share one Burp session.
     */
    private String originFor(Endpoint ep) {
        if (ep != null && ep.sourceFile != null) {
            String o = WebpackParser.originOf(ep.sourceFile);
            if (o != null && !o.isEmpty()) return o;
        }
        return baseOrigin;
    }

    /** Join an origin with a (possibly relative) endpoint path correctly. */
    private static String joinUrl(String origin, String url) {
        if (url.startsWith("http://") || url.startsWith("https://")) return url;
        if (url.startsWith("//")) {
            int i = origin.indexOf("://");
            return (i < 0 ? "http" : origin.substring(0, i)) + ":" + url;
        }
        if (url.startsWith("/")) return origin + url;
        return origin + "/" + url;   // relative path like "chat/history"
    }

    /** Probe endpoints that have NOT been probed yet (incremental). */
    private void probeAll() {
        List<Endpoint> all = new ArrayList<>(epModel.rows);
        List<Endpoint> toProbe = new ArrayList<>();
        for (Endpoint ep : all) {
            if (!probeStatus.containsKey(epKey(ep))) toProbe.add(ep);
        }
        if (toProbe.isEmpty()) {
            JOptionPane.showMessageDialog(null,
                    "All endpoints have already been probed.",
                    "Probe endpoints", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int skipped = all.size() - toProbe.size();
        int r = JOptionPane.showConfirmDialog(null,
                "This will send one request per NEW endpoint (" + toProbe.size()
                        + " new; " + skipped + " already probed will be skipped).\n\n"
                        + "WARNING: mutating methods (DELETE / PUT / POST / PATCH) may cause\n"
                        + "irreversible business operations on the target.\n\n"
                        + "Make sure you are authorized and the target is safe to test.\n\nProceed?",
                "Probe endpoints", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (r != JOptionPane.OK_OPTION) return;
        new Thread(() -> {
            for (Endpoint ep : toProbe) {
                String key = ep.method + "|" + ep.url;
                try {
                    HttpRequest req = endpointRequest(ep);
                    HttpRequestResponse rr = api.http().sendRequest(req);
                    HttpResponse resp = rr.response();
                    probeStatus.put(key, (int) resp.statusCode());
                    epReqStore.put(key, req);
                    epRespStore.put(key, resp);
                    scanProbeResponse(ep, resp);
                } catch (Exception ex) {
                    probeStatus.put(key, -1);
                }
                refreshEndpointTable();
            }
        }).start();
    }

    // ==================================================================
    // Findings / risk
    // ==================================================================
    private String epKey(Endpoint ep) {
        return ep.method + "|" + ep.url;
    }

    /** Union of definition-level params + all call-site fields (a single call site is often empty). */
    private static Set<String> allFieldNames(Endpoint ep) {
        return ep.allFieldNames();
    }

    /** Short single-line snippet of the source around pos (for the evidence/source column). */
    private static String snippetAround(String body, int pos) {
        int start = Math.max(0, pos - 160);
        int end = Math.min(body.length(), pos + 400);
        String s = body.substring(start, end).replaceAll("\\s+", " ").trim();
        return (start > 0 ? "…" : "") + s + (end < body.length() ? "…" : "");
    }

    /** Multi-line snippet (larger window) for the hover tooltip. */
    private static String snippetMultiLine(String body, int pos) {
        int start = Math.max(0, pos - 300);
        int end = Math.min(body.length(), pos + 1000);
        String s = body.substring(start, end);
        return (start > 0 ? "…\n" : "") + s + (end < body.length() ? "\n…" : "");
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private List<String> fieldNames(Endpoint ep) {
        return new ArrayList<>(allFieldNames(ep));
    }

    private void recordFinding(Endpoint ep, RiskScanner.Finding f, HttpRequest req, HttpResponse resp,
                               String highlight) {
        String key = epKey(ep);
        // dedup into findingsByEndpoint (for the Risk column)
        List<RiskScanner.Finding> list = findingsByEndpoint.computeIfAbsent(key, k -> new ArrayList<>());
        synchronized (list) {
            for (RiskScanner.Finding existing : list) {
                if (existing.kind.equals(f.kind) && existing.location.equals(f.location)
                        && java.util.Objects.equals(existing.evidence, f.evidence)) return;
            }
            list.add(f);
        }
        // flat record for the Findings tab
        String rid = key + "|" + f.kind + "|" + f.location + "|" + (f.evidence != null ? f.evidence.hashCode() : 0);
        if (!findingRecords.containsKey(rid)) {
            findingRecords.put(rid, new FindingRecord(nextFindingId.getAndIncrement(),
                    ep.method, ep.url, f, req, resp, highlight));
            refreshFindings();
        }
    }

    private void refreshFindings() {
        List<FindingRecord> recs = new ArrayList<>(findingRecords.values());
        recs.sort((a, b) -> Long.compare(a.id, b.id));
        SwingUtilities.invokeLater(() -> {
            if (findingsModel != null) {
                findingsModel.set(recs);
                if (findingsTable != null) {
                    findingsTable.revalidate();
                    findingsTable.repaint();
                }
            }
            // Live-update the Endpoints Risk column too.
            if (epModel != null) epModel.fireTableDataChanged();
            if (epTable != null) epTable.repaint();
        });
    }

    /** Live-refresh the Endpoints table (Status + Risk) from any background thread. */
    private void refreshEndpointTable() {
        SwingUtilities.invokeLater(() -> {
            if (epModel != null) epModel.fireTableDataChanged();
            if (epTable != null) {
                epTable.revalidate();
                epTable.repaint();
            }
        });
    }

    /** Passive: flag id-like parameters as IDOR hints. */
    private void addIdorFindings(List<Endpoint> eps) {
        for (Endpoint ep : eps) {
            for (String field : fieldNames(ep)) {
                if (RiskScanner.isIdLikeParam(field)) {
                    recordFinding(ep, new RiskScanner.Finding(
                            "IDOR_PARAM", RiskScanner.Severity.LOW, field, field), null, null, null);
                }
            }
        }
    }

    /** Passive: scan all collected JS file bodies for hardcoded secrets, tokens, and internal leakage. */
    private void scanJsBodiesForFindings(List<Endpoint> eps) {
        Map<String, Endpoint> epBySource = new HashMap<>();
        for (Endpoint ep : eps) {
            if (ep.sourceFile != null && !epBySource.containsKey(ep.sourceFile)) {
                epBySource.put(ep.sourceFile, ep);
            }
        }
        for (Map.Entry<String, String> entry : bodies.entrySet()) {
            String url = entry.getKey();
            String body = entry.getValue();
            if (body == null || body.isEmpty()) continue;
            List<RiskScanner.Finding> findings = RiskScanner.scanResponse(body, null);
            if (findings.isEmpty()) continue;
            Endpoint ep = epBySource.get(url);
            if (ep == null && !eps.isEmpty()) {
                ep = eps.get(0);
            }
            if (ep != null) {
                for (RiskScanner.Finding f : findings) {
                    recordFinding(ep, f, reqStore.get(url), respStore.get(url), f.evidence);
                }
            }
        }
    }

    /** Passive scan of a probe response (secrets / deser magic / PII / internal). */
    private void scanProbeResponse(Endpoint ep, HttpResponse resp) {
        try {
            String body = resp.bodyToString();
            byte[] raw = resp.body().getBytes();
            for (RiskScanner.Finding f : RiskScanner.scanResponse(body, raw)) {
                recordFinding(ep, f, epReqStore.get(epKey(ep)), resp, f.evidence);
            }
        } catch (Exception e) {
            api.logging().logToError("[JSCollector] scan failed " + epKey(ep) + " : " + e);
        }
    }

    private void updateProgress(String msg) {
        SwingUtilities.invokeLater(() -> { if (statusLabel != null) statusLabel.setText(msg); });
    }

    // ==================================================================
    // Report export / auto-save (Burp does NOT persist extension state)
    // ==================================================================
    private void exportReport() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("jscollector-report.json"));
        if (fc.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        String path = fc.getSelectedFile().getAbsolutePath();
        if (saveReportTo(path)) {
            JOptionPane.showMessageDialog(null,
                    "Report exported to:\n" + path,
                    "Export report", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null,
                    "Failed to export report to:\n" + path,
                    "Export report", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void autoSave() {
        try {
            String dir = System.getProperty("user.home") + java.io.File.separator + ".BurpJsCollector";
            java.io.File d = new java.io.File(dir);
            if (!d.exists()) d.mkdirs();
            saveReportTo(dir + java.io.File.separator + "autosave-report.json");
        } catch (Exception e) {
            api.logging().logToError("[JSCollector] autosave failed: " + e);
        }
    }

    private boolean saveReportTo(String path) {
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get(path),
                    buildReportJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            api.logging().logToOutput("[JSCollector] saved report to " + path);
            return true;
        } catch (Exception e) {
            api.logging().logToError("[JSCollector] save report failed: " + e);
            return false;
        }
    }

    private String buildReportJson() {
        StringBuilder sb = new StringBuilder();
        List<Endpoint> eps = new ArrayList<>(epModel.rows);
        sb.append("{\n  \"exportedAt\": ").append(System.currentTimeMillis())
          .append(",\n  \"endpoints\": [");
        for (int i = 0; i < eps.size(); i++) {
            if (i > 0) sb.append(",");
            Endpoint ep = eps.get(i);
            String key = epKey(ep);
            sb.append("\n    {\"id\":").append(ep.id)
              .append(",\"method\":\"").append(esc(ep.method)).append("\"")
              .append(",\"url\":\"").append(esc(ep.url)).append("\"")
              .append(",\"address\":\"").append(esc(joinUrl(originFor(ep), ep.url))).append("\"")
              .append(",\"key\":\"").append(esc(ep.exportKey)).append("\"")
              .append(",\"calls\":").append(ep.callSites.size())
              .append(",\"params\":[").append(paramsJson(ep)).append("]")
              .append(",\"paramValues\":").append(paramValuesJson(ep))
              .append(",\"status\":").append(statusOf(ep))
              .append(",\"findings\":[").append(findingsJson(key)).append("]")
              .append("}");
        }
        sb.append("\n  ]\n}\n");
        return sb.toString();
    }

    private String paramsJson(Endpoint ep) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (String f : fieldNames(ep)) {
            if (i++ > 0) sb.append(",");
            sb.append("\"").append(esc(f)).append("\"");
        }
        return sb.toString();
    }

    private String paramValuesJson(Endpoint ep) {
        Map<String, String> values = ep.paramValues();
        if (values.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder("{");
        int i = 0;
        for (Map.Entry<String, String> e : values.entrySet()) {
            if (i++ > 0) sb.append(",");
            sb.append("\"").append(esc(e.getKey())).append("\":\"").append(esc(e.getValue())).append("\"");
        }
        return sb.append("}").toString();
    }

    private int statusOf(Endpoint ep) {
        Integer s = probeStatus.get(epKey(ep));
        return s == null ? -1 : s;
    }

    private String findingsJson(String key) {
        List<RiskScanner.Finding> fs = findingsByEndpoint.get(key);
        if (fs == null || fs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (RiskScanner.Finding f : fs) {
            if (i++ > 0) sb.append(",");
            sb.append("{\"severity\":\"").append(f.severity).append("\"")
              .append(",\"kind\":\"").append(esc(f.kind)).append("\"")
              .append(",\"location\":\"").append(esc(f.location)).append("\"")
              .append(",\"evidence\":\"").append(esc(f.evidence)).append("\"");
            if (f.baselineLen >= 0) {
                sb.append(",\"baselineStatus\":").append(f.baselineStatus)
                  .append(",\"baselineLen\":").append(f.baselineLen)
                  .append(",\"probeStatus\":").append(f.probeStatus)
                  .append(",\"probeLen\":").append(f.probeLen);
            }
            sb.append("}");
        }
        return sb.toString();
    }

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    // ==================================================================
    // Table models
    // ==================================================================
    private static class JsTableModel extends AbstractTableModel {
        final String[] COLS = {"ID", "URL", "Host", "Status", "Size", "Source", "Webpack", "Map"};
        final JsHarvester h;
        List<JsEntry> rows = new ArrayList<>();
        JsTableModel(JsHarvester h) { this.h = h; }

        void refresh() {
            rows = h.entries();
            rows.sort((a, b) -> Long.compare(a.id, b.id));
            fireTableDataChanged();
        }

        JsEntry row(int i) { return rows.get(i); }

        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return COLS.length; }
        public String getColumnName(int c) { return COLS[c]; }
        public Object getValueAt(int r, int c) {
            JsEntry e = rows.get(r);
            switch (c) {
                case 0: return e.id;
                case 1: return e.url;
                case 2: return e.host;
                case 3: return e.status == 0 ? "-" : e.status;
                case 4: return e.size;
                case 5: return e.src;
                case 6: return e.isWebpack ? "Y" : "";
                case 7: return e.hasMap ? "Y" : "";
            }
            return "";
        }
    }

    private static class EndpointTableModel extends AbstractTableModel {
        final String[] COLS = {"ID", "Method", "URL", "Params", "Status", "Risk", "Source"};
        final Map<String, Integer> probeStatus;
        final Map<String, List<RiskScanner.Finding>> findings;
        List<Endpoint> rows = new ArrayList<>();
        EndpointTableModel(Map<String, Integer> probeStatus,
                           Map<String, List<RiskScanner.Finding>> findings) {
            this.probeStatus = probeStatus;
            this.findings = findings;
        }
        void set(List<Endpoint> eps) {
            rows = new ArrayList<>(eps);
            rows.sort((a, b) -> Long.compare(a.id, b.id));
            fireTableDataChanged();
        }
        void append(Endpoint ep) {
            rows.add(ep);
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }
        Endpoint row(int i) { return rows.get(i); }
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return COLS.length; }
        public String getColumnName(int c) { return COLS[c]; }
        public Object getValueAt(int r, int c) {
            Endpoint ep = rows.get(r);
            switch (c) {
                case 0: return ep.id;
                case 1: return ep.method;
                case 2: return ep.url;
                case 3: return fieldsOf(ep);
                case 4: return statusOf(ep);
                case 5: return riskText(ep);
                case 6: return ep.defSnippet;
            }
            return "";
        }

        private String keyOf(Endpoint ep) { return ep.method + "|" + ep.url; }

        private String riskText(Endpoint ep) {
            List<RiskScanner.Finding> fs = findings.get(keyOf(ep));
            if (fs != null && !fs.isEmpty()) {
                RiskScanner.Finding top = highest(fs);
                return top.severity + ":" + top.kind;
            }
            if (!probeStatus.containsKey(keyOf(ep))) return "Not probed";
            return "Clear";
        }

        RiskScanner.Severity severityAt(int modelRow) {
            List<RiskScanner.Finding> fs = findings.get(keyOf(rows.get(modelRow)));
            return (fs == null || fs.isEmpty()) ? null : highest(fs).severity;
        }

        boolean notProbedAt(int modelRow) {
            Endpoint ep = rows.get(modelRow);
            return !probeStatus.containsKey(keyOf(ep))
                    && (findings.get(keyOf(ep)) == null || findings.get(keyOf(ep)).isEmpty());
        }

        private RiskScanner.Finding highest(List<RiskScanner.Finding> fs) {
            RiskScanner.Finding top = fs.get(0);
            for (RiskScanner.Finding f : fs) {
                if (f.severity.ordinal() < top.severity.ordinal()) top = f;
            }
            return top;
        }

        private Object statusOf(Endpoint ep) {
            Integer s = probeStatus.get(ep.method + "|" + ep.url);
            return s == null ? "" : (s < 0 ? "ERR" : s);
        }

        private String fieldsOf(Endpoint ep) {
            StringBuilder sb = new StringBuilder();
            Set<String> fields = new LinkedHashSet<>(allFieldNames(ep));
            fields.addAll(ep.pathParams());
            if (!fields.isEmpty()) sb.append("params:").append(fields);
            if (!ep.headerFields.isEmpty()) {
                if (sb.length() > 0) sb.append(" ");
                sb.append("headers:").append(ep.headerFields);
            }
            return sb.length() == 0 ? "[]" : sb.toString();
        }
    }

    private static boolean isDark(Component comp) {
        Color bg = comp.getBackground();
        if (bg == null) bg = UIManager.getColor("Table.background");
        if (bg == null) return false;
        double luma = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return luma < 128;
    }

    private class RiskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                int mr = table.convertRowIndexToModel(row);
                RiskScanner.Severity sev = epModel.severityAt(mr);
                boolean notProbed = epModel.notProbedAt(mr);
                boolean dark = isDark(table);
                if (notProbed) {
                    c.setBackground(dark ? new Color(45, 45, 48) : new Color(240, 240, 240));
                    c.setForeground(dark ? new Color(170, 170, 170) : Color.DARK_GRAY);
                } else if (sev == RiskScanner.Severity.HIGH) {
                    c.setBackground(dark ? new Color(95, 30, 30) : new Color(255, 205, 205));
                    c.setForeground(dark ? new Color(255, 190, 190) : Color.BLACK);
                } else if (sev == RiskScanner.Severity.MEDIUM) {
                    c.setBackground(dark ? new Color(85, 60, 20) : new Color(255, 225, 180));
                    c.setForeground(dark ? new Color(255, 220, 160) : Color.BLACK);
                } else if (sev == RiskScanner.Severity.LOW) {
                    c.setBackground(dark ? new Color(65, 65, 25) : new Color(255, 248, 190));
                    c.setForeground(dark ? new Color(255, 248, 180) : Color.BLACK);
                } else {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    private class FindingsCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                int mr = table.convertRowIndexToModel(row);
                RiskScanner.Severity sev = findingsModel.rows.get(mr).finding.severity;
                boolean dark = isDark(table);
                if (sev == RiskScanner.Severity.HIGH) {
                    c.setBackground(dark ? new Color(95, 30, 30) : new Color(255, 205, 205));
                    c.setForeground(dark ? new Color(255, 190, 190) : Color.BLACK);
                } else if (sev == RiskScanner.Severity.MEDIUM) {
                    c.setBackground(dark ? new Color(85, 60, 20) : new Color(255, 225, 180));
                    c.setForeground(dark ? new Color(255, 220, 160) : Color.BLACK);
                } else if (sev == RiskScanner.Severity.LOW) {
                    c.setBackground(dark ? new Color(65, 65, 25) : new Color(255, 248, 190));
                    c.setForeground(dark ? new Color(255, 248, 180) : Color.BLACK);
                } else {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    private static final class FindingRecord {
        final long id;
        final String method;
        final String url;
        final RiskScanner.Finding finding;
        final HttpRequest request;
        final HttpResponse response;
        final String highlight;

        FindingRecord(long id, String method, String url, RiskScanner.Finding finding,
                      HttpRequest request, HttpResponse response, String highlight) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.finding = finding;
            this.request = request;
            this.response = response;
            this.highlight = highlight;
        }

        String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append('[').append(finding.severity).append("] ").append(finding.kind)
              .append("\nEndpoint: ").append(method).append(' ').append(url)
              .append("\nLocation: ").append(finding.location)
              .append("\nEvidence: ").append(finding.evidence);
            if (finding.baselineLen >= 0) {
                sb.append("\nbaseline ").append(finding.baselineStatus).append(" / ")
                  .append(finding.baselineLen).append("B   ->   probe ").append(finding.probeStatus)
                  .append(" / ").append(finding.probeLen).append('B');
            }
            return sb.toString();
        }
    }

    private static class FindingsTableModel extends AbstractTableModel {
        final String[] COLS = {"ID", "Severity", "Kind", "Method", "URL", "Location", "Evidence"};
        List<FindingRecord> rows = new ArrayList<>();
        void set(List<FindingRecord> recs) {
            rows = new ArrayList<>(recs);
            fireTableDataChanged();
        }
        FindingRecord row(int i) { return rows.get(i); }
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return COLS.length; }
        public String getColumnName(int c) { return COLS[c]; }
        public Object getValueAt(int r, int c) {
            FindingRecord rec = rows.get(r);
            switch (c) {
                case 0: return rec.id;
                case 1: return rec.finding.severity;
                case 2: return rec.finding.kind;
                case 3: return rec.method;
                case 4: return rec.url;
                case 5: return rec.finding.location;
                case 6: return rec.finding.evidence.length() > 60
                        ? rec.finding.evidence.substring(0, 60) + "..." : rec.finding.evidence;
            }
            return "";
        }
    }
}
