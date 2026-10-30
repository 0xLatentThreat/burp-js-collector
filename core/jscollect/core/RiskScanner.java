package jscollect.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive risk rules + SQLi probe signal helpers (Burp-independent, unit-testable).
 *
 * Passive rules run on probe responses (and can run on collected JS bodies):
 *   - DESER      : serialization magic bytes / markers
 *   - SECRET     : API keys, tokens, private keys, passwords, JDBC strings
 *   - PII        : CN id card, mobile, email
 *   - INTERNAL   : private IP, stack trace, SQL statement leakage
 *
 * SQLi probe helpers:
 *   - isIdLikeParam  : flag id-like parameters (IDOR hint)
 *   - containsSqlError : SQL error keyword detection (strong signal)
 */
public final class RiskScanner {

    public enum Severity { HIGH, MEDIUM, LOW }

    public static final class Finding {
        public final String kind;      // DESER / SECRET / PII / INTERNAL / SQLI / IDOR_PARAM / RESP_ANOMALY
        public final Severity severity;
        public final String location;  // parameter name / header name / "body"
        public final String evidence;  // truncated snippet
        public int baselineLen = -1, probeLen = -1, baselineStatus = -1, probeStatus = -1;

        public Finding(String kind, Severity severity, String location, String evidence) {
            this.kind = kind;
            this.severity = severity;
            this.location = location;
            this.evidence = evidence;
        }
    }

    // Case handling is per-alternative (no global CASE_INSENSITIVE) so that AWS key IDs
    // stay uppercase-only and don't false-positive on mixed-case strings like "AKIAAACi...".
    private static final Pattern SECRET = Pattern.compile(
        "(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"
        + "|xox[baprs]-[0-9A-Za-z-]{10,}"
        + "|ghp_[0-9A-Za-z]{36}"
        + "|-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
        + "|(?i:password|passwd|pwd)\\s*[\"']?\\s*[:=]\\s*[\"'][^\"']{4,}[\"']"
        + "|(?i:jdbc:[a-z0-9]+:[^\"'\\s]+)");

    private static final Pattern PII = Pattern.compile(
        "\\b[1-9]\\d{5}(18|19|20)\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]\\b"
        + "|\\b1[3-9]\\d{9}\\b"
        + "|\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");

    private static final Pattern INTERNAL = Pattern.compile(
        "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"
        + "|(?:Traceback \\(most recent call last\\)|Caused by:|at [\\w.$]+\\([^)]*\\.java:\\d+\\))"
        + "|(?i)\\b(?:SELECT\\s+[\\w.*,]+\\s+FROM|INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM)\\b");

    private static final Pattern PHP_SERIALIZED = Pattern.compile("\\b(?:O|a):\\d+:");

    private static final String[] SQL_ERRORS = {
        "SQL syntax", "You have an error in your SQL", "unclosed quotation mark",
        "SQLSTATE", "syntax error at or near", "Microsoft OLE DB Provider",
        "mysql_fetch", "Warning: mysql", "SQLException", "ORA-", "near \""
    };

    private static final List<String> NON_ID_WORDS = Arrays.asList(
        "grid", "valid", "rapid", "solid", "paid", "avoid", "void", "acid", "arid", "overrid");

    private RiskScanner() {}

    /** Passive scan of a probe response (body text + raw bytes for magic detection). */
    public static List<Finding> scanResponse(String body, byte[] raw) {
        List<Finding> out = new ArrayList<>();
        Finding d = detectDeser(raw, body);
        if (d != null) out.add(d);
        out.addAll(scanPattern(body, SECRET, "SECRET", Severity.HIGH));
        String sqlErr = findSqlError(body);
        if (sqlErr != null) {
            out.add(new Finding("SQL_ERROR", Severity.HIGH, "body", "Database error keyword: " + sqlErr));
        }
        out.addAll(scanPattern(body, PII, "PII", Severity.MEDIUM));
        out.addAll(scanPattern(body, INTERNAL, "INTERNAL", Severity.MEDIUM));
        return out;
    }

    private static Finding detectDeser(byte[] raw, String body) {
        if (raw != null && raw.length >= 4) {
            if ((raw[0] & 0xff) == 0xac && (raw[1] & 0xff) == 0xed
                    && (raw[2] & 0xff) == 0x00 && (raw[3] & 0xff) == 0x05) {
                return new Finding("DESER", Severity.HIGH, "body", "Java serialization (ac ed 00 05)");
            }
            if ((raw[0] & 0xff) == 0x00 && (raw[1] & 0xff) == 0x01
                    && (raw[2] & 0xff) == 0x00 && (raw[3] & 0xff) == 0x00) {
                return new Finding("DESER", Severity.HIGH, "body", ".NET BinaryFormatter (00 01 00 00)");
            }
            if ((raw[0] & 0xff) == 0x80 && (raw[1] & 0xff) >= 0x01 && (raw[1] & 0xff) <= 0x05) {
                return new Finding("DESER", Severity.HIGH, "body", "Python pickle protocol " + (raw[1] & 0xff));
            }
        }
        if (body != null) {
            Matcher m = PHP_SERIALIZED.matcher(body);
            if (m.find()) return new Finding("DESER", Severity.HIGH, "body", m.group());
        }
        return null;
    }

    private static List<Finding> scanPattern(String body, Pattern p, String kind, Severity sev) {
        List<Finding> out = new ArrayList<>();
        if (body == null) return out;
        Matcher m = p.matcher(body);
        while (m.find() && out.size() < 5) {
            String ev = m.group();
            out.add(new Finding(kind, sev, "body",
                    ev.length() > 120 ? ev.substring(0, 120) + "..." : ev));
        }
        return out;
    }

    /** IDOR hint: parameter name looks like an object identifier. */
    public static boolean isIdLikeParam(String name) {
        if (name == null) return false;
        String n = name.toLowerCase();
        if (n.length() < 2) return false;
        if (NON_ID_WORDS.contains(n)) return false;
        return n.equals("id") || n.endsWith("id") || n.endsWith("no")
                || n.endsWith("num") || n.endsWith("code");
    }

    /** Strong SQLi signal: response body contains a SQL error keyword. */
    public static boolean containsSqlError(String body) {
        return findSqlError(body) != null;
    }

    /** Return the matched SQL error keyword (for highlighting), or null. */
    public static String findSqlError(String body) {
        if (body == null) return null;
        for (String k : SQL_ERRORS) {
            if (body.contains(k)) return k;
        }
        return null;
    }
}
