package jscollect.core;

/** Metadata for one collected JS resource (body is not kept in memory here). */
public final class JsEntry {
    public long id;              // monotonic id assigned on first sight (ascending = arrival order)
    public final String url;
    public final String host;
    public final String src;      // proxy | html | runtime | sourcemap
    public int status;            // 0 = not fetched yet
    public int size;
    public boolean isWebpack;
    public boolean hasMap;
    public String mapUrl;

    public JsEntry(String url, String src) {
        this.url = url;
        this.host = WebpackParser.hostOf(url);
        this.src = src;
    }

    @Override
    public String toString() {
        return "JsEntry[" + src + " " + url + " status=" + status + " size=" + size
                + " webpack=" + isWebpack + " map=" + hasMap + "]";
    }
}
