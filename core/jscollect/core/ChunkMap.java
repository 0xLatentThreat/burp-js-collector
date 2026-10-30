package jscollect.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** A webpack chunk map: filename-template prefix + (id -> hash). */
public final class ChunkMap {
    public final String prefix;
    public final Map<String, String> entries;

    public ChunkMap(String prefix, Map<String, String> entries) {
        this.prefix = prefix;
        this.entries = new LinkedHashMap<>(entries);
    }

    @Override
    public String toString() {
        return "ChunkMap(prefix=" + prefix + ", entries=" + entries.size() + ")";
    }
}
