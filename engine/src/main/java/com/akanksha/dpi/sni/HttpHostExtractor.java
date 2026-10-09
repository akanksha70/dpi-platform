package com.akanksha.dpi.sni;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/** Reads the Host header from a plain (unencrypted) HTTP request. */
public final class HttpHostExtractor {
    private static final Set<String> METHOD_PREFIXES =
            Set.of("GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI");

    private HttpHostExtractor() {}

    public static Optional<String> extract(byte[] packetData, int payloadOffset, int payloadLength) {
        if (payloadOffset < 0 || payloadLength <= 0 || payloadOffset + payloadLength > packetData.length) {
            return Optional.empty();
        }
        return extract(Arrays.copyOfRange(packetData, payloadOffset, payloadOffset + payloadLength));
    }

    public static boolean isHttpRequest(byte[] p) {
        if (p.length < 4) return false;
        return METHOD_PREFIXES.contains(new String(p, 0, 4, StandardCharsets.US_ASCII));
    }

    public static Optional<String> extract(byte[] p) {
        if (!isHttpRequest(p)) return Optional.empty();
        int len = p.length;

        for (int i = 0; i + 6 < len; i++) {
            // case-insensitive match of "host:"
            if ((p[i] == 'H' || p[i] == 'h')
                    && (p[i + 1] == 'o' || p[i + 1] == 'O')
                    && (p[i + 2] == 's' || p[i + 2] == 'S')
                    && (p[i + 3] == 't' || p[i + 3] == 'T')
                    && p[i + 4] == ':') {

                int start = i + 5;
                while (start < len && (p[start] == ' ' || p[start] == '\t')) start++;

                int end = start;
                while (end < len && p[end] != '\r' && p[end] != '\n') end++;

                if (end > start) {
                    String host = new String(p, start, end - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');          // remove ":port" if present
                    if (colon >= 0) host = host.substring(0, colon);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }
}