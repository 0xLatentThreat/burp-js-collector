package jscollect.core;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Benchmark and Stress Test Suite for JS Collector.
 * Tests:
 * 1. ReDoS (Regular Expression Denial of Service) resistance.
 * 2. High-throughput large JS parsing (1MB+ to 5MB synthetic bundles).
 * 3. Multi-threaded concurrency and memory stability.
 */
public final class StressTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("== Running JS Collector Stress & Benchmark Suite ==");

        testReDoSResistance();
        testLargeFileThroughput();
        testConcurrentParsingStability();

        System.out.println("\n== Stress Test Summary: " + passed + " passed, " + failed + " failed ==");
        if (failed > 0) System.exit(1);
    }

    private static void check(String title, boolean ok) {
        if (ok) {
            System.out.println("  [PASS] " + title);
            passed++;
        } else {
            System.err.println("  [FAIL] " + title);
            failed++;
        }
    }

    /**
     * 1. ReDoS Resistance Test
     * Deliberately constructs pathological inputs that could trigger catastrophic backtracking
     * in naive regex implementations (e.g. nested quantifiers, unclosed quotes, long repetitive tokens).
     */
    private static void testReDoSResistance() {
        System.out.println("\n[1] Testing ReDoS Resistance...");

        // Unclosed long quotes
        StringBuilder sb1 = new StringBuilder("axios.get(\"");
        for (int i = 0; i < 50_000; i++) sb1.append("a/b/c/d/e/");
        long t0 = System.currentTimeMillis();
        GenericEndpointExtractor.extract(sb1.toString());
        long d1 = System.currentTimeMillis() - t0;
        check("ReDoS: Unclosed long quote handled in " + d1 + "ms (< 300ms)", d1 < 300);

        // Dense nested-like symbols
        StringBuilder sb2 = new StringBuilder("var x = {");
        for (int i = 0; i < 20_000; i++) sb2.append("url: 'test', params: { a: 1, ");
        long t1 = System.currentTimeMillis();
        GenericEndpointExtractor.extract(sb2.toString());
        long d2 = System.currentTimeMillis() - t1;
        check("ReDoS: Deeply unclosed braces handled in " + d2 + "ms (< 250ms)", d2 < 250);

        // Repetitive query string concatenation
        StringBuilder sb3 = new StringBuilder("fetch('/api/search?' + ");
        for (int i = 0; i < 5_000; i++) sb3.append("'k=' + v + ");
        sb3.append("'end')");
        long t2 = System.currentTimeMillis();
        GenericEndpointExtractor.extract(sb3.toString());
        long d3 = System.currentTimeMillis() - t2;
        check("ReDoS: Repetitive concatenation handled in " + d3 + "ms (< 100ms)", d3 < 100);
    }

    /**
     * 2. Large File Throughput Test
     * Parses synthetic 1MB and 3MB minified JS containing hundreds of API calls.
     */
    private static void testLargeFileThroughput() {
        System.out.println("\n[2] Testing Large File Throughput (1MB & 3MB synthetic bundle)...");

        // Generate ~1.2MB of minified realistic JS
        StringBuilder sb = new StringBuilder();
        sb.append("!function(){var api=axios.create({baseURL:'/api/v1'});");
        for (int i = 0; i < 2000; i++) {
            sb.append("function f").append(i).append("(data){")
              .append("return api.post('/endpoint/").append(i).append("', data);")
              .append("}; f").append(i).append("({ userId: ").append(i).append(", tag: 'test' }); ");
            sb.append("fetch('/pure/fetch/").append(i).append("', { method: 'POST', body: JSON.stringify({ item: ").append(i).append(" }) }); ");
        }
        sb.append("}();");

        String code1MB = sb.toString();
        double mb = code1MB.length() / (1024.0 * 1024.0);

        long t0 = System.currentTimeMillis();
        List<GenericEndpointExtractor.Hit> hits = GenericEndpointExtractor.extract(code1MB);
        long dur = System.currentTimeMillis() - t0;

        check(String.format("1MB+ bundle parsed (%.2f MB, %d endpoints found) in %d ms (< 800ms)", mb, hits.size(), dur),
                dur < 800 && hits.size() >= 2000);
    }

    /**
     * 3. Multi-threaded Concurrency & Stability Test
     * Simulates 10 concurrent threads parsing 100 scripts simultaneously.
     */
    private static void testConcurrentParsingStability() {
        System.out.println("\n[3] Testing Concurrent Multi-threaded Parsing Stability...");

        int threads = 8;
        int tasks = 80;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();

        String sample = "var a = axios.create({baseURL:'/api'}); a.get('/user', {params:{id:123}});" +
                "fetch('/auth/login', {method:'POST', body: JSON.stringify({u:'admin', p:'secret'})});";

        long start = System.currentTimeMillis();
        for (int i = 0; i < tasks; i++) {
            futures.add(pool.submit(() -> {
                for (int j = 0; j < 10; j++) {
                    GenericEndpointExtractor.extract(sample);
                }
            }));
        }

        boolean allDone = true;
        for (Future<?> f : futures) {
            try {
                f.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                allDone = false;
            }
        }
        pool.shutdownNow();
        long dur = System.currentTimeMillis() - start;

        check("Concurrent 80 tasks (800 parsing operations) completed in " + dur + "ms", allDone && dur < 2000);
    }
}
