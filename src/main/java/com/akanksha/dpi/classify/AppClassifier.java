package com.akanksha.dpi.classify;

import com.akanksha.dpi.model.AppType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Maps a domain name to an app using an ordered signature list (first match wins). */
public final class AppClassifier {

    private record Signature(AppType app, List<String> domains) {}

    private final List<Signature> signatures;

    private AppClassifier(List<Signature> signatures) {
        this.signatures = List.copyOf(signatures);
    }

    public static AppClassifier loadDefault() throws IOException {
        try (InputStream in = AppClassifier.class.getResourceAsStream("/signatures.txt")) {
            if (in == null) throw new IOException("signatures.txt not found on the classpath");
            return parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** Format per line: APP_NAME: domain1, domain2   (blank lines and lines starting with # are ignored). */
    public static AppClassifier parse(String text) {
        List<Signature> list = new ArrayList<>();
        int lineNo = 0;
        for (String raw : text.split("\\R")) {          // "\\R" matches any line break (Windows or Linux)
            lineNo++;
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            int colon = line.indexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException("signatures line " + lineNo + ": missing ':'");
            }
            Optional<AppType> app = AppType.fromString(line.substring(0, colon));
            if (app.isEmpty()) {
                throw new IllegalArgumentException("signatures line " + lineNo + ": unknown app '"
                        + line.substring(0, colon).trim() + "'");
            }
            List<String> domains = new ArrayList<>();
            for (String d : line.substring(colon + 1).split(",")) {
                if (!d.isBlank()) domains.add(d.trim());
            }
            list.add(new Signature(app.get(), domains));
        }
        return new AppClassifier(list);
    }

    /** No host -> UNKNOWN. Host present but not in the list -> HTTPS (same as the C++ version). */
    public AppType classify(String host) {
        if (host == null || host.isBlank()) return AppType.UNKNOWN;
        for (Signature s : signatures) {
            for (String d : s.domains()) {
                if (DomainMatcher.matches(host, d)) return s.app();
            }
        }
        return AppType.HTTPS;
    }
}