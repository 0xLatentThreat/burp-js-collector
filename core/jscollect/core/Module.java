package jscollect.core;

/** A webpack module: id + body + start/end offsets within the source. */
public final class Module {
    public final String id;
    public final String body;
    public final int start;   // module definition start offset (includes "id:")
    public final int end;     // next module definition start (or end of file)

    public Module(String id, String body, int start, int end) {
        this.id = id;
        this.body = body;
        this.start = start;
        this.end = end;
    }
}
