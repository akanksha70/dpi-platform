package com.akanksha.dpi.classify;

import java.util.Locale;

public final class DomainMatcher {
    private DomainMatcher() {}

    /** True if host equals domain or is a subdomain of it ("www.x.com" matches "x.com"; "netflix.com" does not). */
    public static boolean matches(String host, String domain) {
        if (host == null || domain == null) return false;
        String h = normalize(host);
        String d = normalize(domain);
        if (h.isEmpty() || d.isEmpty()) return false;
        return h.equals(d) || h.endsWith("." + d);
    }

    static String normalize(String s) {
        String t = s.trim().toLowerCase(Locale.ROOT);   // Locale.ROOT avoids language-specific lowercasing quirks
        while (t.endsWith(".")) t = t.substring(0, t.length() - 1);
        return t;
    }
}