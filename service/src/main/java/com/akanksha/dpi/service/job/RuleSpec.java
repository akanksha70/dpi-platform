package com.akanksha.dpi.service.job;

import com.akanksha.dpi.engine.Rules;
import com.akanksha.dpi.model.AppType;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** The block rules a caller asked for, already cleaned and validated. */
public record RuleSpec(List<String> blockIps, List<String> blockApps, List<String> blockDomains) {

    private static final int MAX_ENTRIES = 100;

    public RuleSpec {
        blockIps = List.copyOf(blockIps);
        blockApps = List.copyOf(blockApps);
        blockDomains = List.copyOf(blockDomains);
    }

    public static RuleSpec empty() {
        return new RuleSpec(List.of(), List.of(), List.of());
    }

    /** Cleans and validates raw user input. Throws InvalidInputException on the first problem. */
    public static RuleSpec of(List<String> ips, List<String> apps, List<String> domains) {
        return new RuleSpec(cleanIps(ips), cleanApps(apps), cleanDomains(domains));
    }

    public Rules toRules() {
        Rules rules = new Rules();
        blockIps.forEach(rules::blockIp);
        blockApps.forEach(rules::blockApp);
        blockDomains.forEach(rules::blockDomain);
        return rules;
    }

        /** Combines two rule sets, keeping order and dropping duplicates. */
    public RuleSpec merge(RuleSpec other) {
        return new RuleSpec(
                union(blockIps, other.blockIps),
                union(blockApps, other.blockApps),
                union(blockDomains, other.blockDomains));
    }

    private static List<String> union(List<String> first, List<String> second) {
        Set<String> out = new LinkedHashSet<>(first);
        out.addAll(second);
        return new ArrayList<>(out);
    }

    private static List<String> cleanIps(List<String> raw) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : nonNull(raw)) {
            String t = s.trim();
            if (t.isEmpty()) continue;
            String normalized = normalizeIpv4(t);
            if (normalized == null) throw new InvalidInputException("Invalid IPv4 address: " + shorten(t));
            out.add(normalized);
        }
        return limited(out, "blockIp");
    }

    private static List<String> cleanApps(List<String> raw) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : nonNull(raw)) {
            String t = s.trim();
            if (t.isEmpty()) continue;
            AppType app = AppType.fromString(t).orElseThrow(() -> new InvalidInputException(
                    "Unknown app: " + shorten(t) + " (use names like YouTube, Facebook or Twitter/X)"));
            out.add(app.displayName());
        }
        return limited(out, "blockApp");
    }

    private static List<String> cleanDomains(List<String> raw) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : nonNull(raw)) {
            String t = s.trim().toLowerCase(java.util.Locale.ROOT);
            while (t.endsWith(".")) t = t.substring(0, t.length() - 1);
            if (t.isEmpty()) continue;
            if (!isDomain(t)) throw new InvalidInputException("Invalid domain: " + shorten(t));
            out.add(t);
        }
        return limited(out, "blockDomain");
    }

    /** Returns the address in canonical form ("192.168.001.050" becomes "192.168.1.50"), or null if invalid. */
    private static String normalizeIpv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) return null;
            for (char c : p.toCharArray()) {
                if (c < '0' || c > '9') return null;
            }
            int n = Integer.parseInt(p);
            if (n > 255) return null;
            if (i > 0) sb.append('.');
            sb.append(n);
        }
        return sb.toString();
    }

    private static boolean isDomain(String d) {
        if (d.length() > 253 || d.indexOf('.') < 0) return false;
        for (String label : d.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) return false;
            if (label.startsWith("-") || label.endsWith("-")) return false;
            for (char c : label.toCharArray()) {
                boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) return false;
            }
        }
        return true;
    }

    private static List<String> nonNull(List<String> list) {
        return list == null ? List.of() : list;
    }

    private static List<String> limited(Set<String> values, String name) {
        if (values.size() > MAX_ENTRIES) {
            throw new InvalidInputException("Too many " + name + " values (maximum " + MAX_ENTRIES + ")");
        }
        return new ArrayList<>(values);
    }

    private static String shorten(String s) {
        return s.length() > 50 ? s.substring(0, 50) + "..." : s;
    }
}