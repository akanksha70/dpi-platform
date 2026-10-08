
package com.akanksha.dpi.sni;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

/** Reads the server name out of a TLS Client Hello (the first packet of an HTTPS connection). */
public final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {}

    /** Convenience overload: the payload sits inside a larger packet array. */
    public static Optional<String> extract(byte[] packetData, int payloadOffset, int payloadLength) {
        if (payloadOffset < 0 || payloadLength <= 0 || payloadOffset + payloadLength > packetData.length) {
            return Optional.empty();
        }
        return extract(Arrays.copyOfRange(packetData, payloadOffset, payloadOffset + payloadLength));
    }

    public static boolean isTlsClientHello(byte[] p) {
        int len = p.length;
        if (len < 9) return false;                              // 5-byte record header + 4-byte handshake header
        if (u8(p, 0) != CONTENT_TYPE_HANDSHAKE) return false;   // 0x16 = handshake
        int version = u16(p, 1);
        if (version < 0x0300 || version > 0x0304) return false; // SSL 3.0 .. TLS 1.3
        int recordLength = u16(p, 3);
        if (recordLength > len - 5) return false;               // record not fully inside this packet
        return u8(p, 5) == HANDSHAKE_CLIENT_HELLO;              // 0x01 = Client Hello
    }

    public static Optional<String> extract(byte[] p) {
        if (!isTlsClientHello(p)) return Optional.empty();
        int len = p.length;

        int pos = 5;      // skip the TLS record header
        pos += 4;         // skip the handshake header (type + 3-byte length)
        pos += 2;         // skip client version
        pos += 32;        // skip random

        // Session ID
        if (pos >= len) return Optional.empty();
        pos += 1 + u8(p, pos);

        // Cipher suites
        if (pos + 2 > len) return Optional.empty();
        pos += 2 + u16(p, pos);

        // Compression methods
        if (pos >= len) return Optional.empty();
        pos += 1 + u8(p, pos);

        // Extensions
        if (pos + 2 > len) return Optional.empty();
        int extensionsLength = u16(p, pos);
        pos += 2;
        int extensionsEnd = Math.min(pos + extensionsLength, len);

        while (pos + 4 <= extensionsEnd) {
            int type = u16(p, pos);
            int extLength = u16(p, pos + 2);
            pos += 4;
            if (pos + extLength > extensionsEnd) break;

            if (type == EXTENSION_SNI) {
                if (extLength < 5) break;
                int listLength = u16(p, pos);
                if (listLength < 3) break;
                int nameType = u8(p, pos + 2);
                int nameLength = u16(p, pos + 3);
                if (nameType != SNI_TYPE_HOSTNAME) break;
                if (nameLength > extLength - 5) break;
                return Optional.of(new String(p, pos + 5, nameLength, StandardCharsets.US_ASCII));
            }
            pos += extLength;
        }
        return Optional.empty();
    }

    // Java bytes are signed (-128..127); "& 0xFF" turns them into 0..255.
    private static int u8(byte[] d, int i) {
        return d[i] & 0xFF;
    }

    // Network order = big-endian: the first byte is the high part. "<< 8" shifts it left by 8 bits.
    private static int u16(byte[] d, int i) {
        return (u8(d, i) << 8) | u8(d, i + 1);
    }
}