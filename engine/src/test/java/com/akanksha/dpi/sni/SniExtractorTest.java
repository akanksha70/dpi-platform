package com.akanksha.dpi.sni;

import com.akanksha.dpi.parser.PacketParser;
import com.akanksha.dpi.parser.ParsedPacket;
import com.akanksha.dpi.pcap.PcapReader;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SniExtractorTest {

    // The 18 domains your C++ baseline detected (see docs/baseline_cpp.txt).
    private static final Set<String> EXPECTED = Set.of(
            "httpbin.org", "www.youtube.com", "www.facebook.com", "www.microsoft.com",
            "github.com", "www.instagram.com", "discord.com", "web.telegram.org",
            "www.apple.com", "twitter.com", "example.com", "open.spotify.com",
            "www.google.com", "www.amazon.com", "zoom.us", "www.cloudflare.com",
            "www.netflix.com", "www.tiktok.com");

    @Test
    void findsTheSameDomainsAsTheCppBaseline() throws Exception {
        Set<String> found = new TreeSet<>();

        try (InputStream in = getClass().getResourceAsStream("/test_dpi.pcap")) {
            assertNotNull(in, "test_dpi.pcap not found in src/test/resources");
            try (PcapReader reader = new PcapReader(in)) {
                while (true) {
                    var raw = reader.readNext();
                    if (raw.isEmpty()) break;
                    var parsed = PacketParser.parse(raw.get());
                    if (parsed.isEmpty()) continue;

                    ParsedPacket p = parsed.get();
                    if (!p.hasIp() || (!p.hasTcp() && !p.hasUdp())) continue;

                    byte[] data = raw.get().data();
                    // Same rules as the C++ engine: HTTPS on port 443, plain HTTP on port 80
                    if (p.destPort() == 443 && p.payloadLength() > 5) {
                        SniExtractor.extract(data, p.payloadOffset(), p.payloadLength()).ifPresent(found::add);
                    }
                    if (p.destPort() == 80 && p.payloadLength() > 10) {
                        HttpHostExtractor.extract(data, p.payloadOffset(), p.payloadLength()).ifPresent(found::add);
                    }
                }
            }
        }

        System.out.println("Domains found: " + found.size());
        found.forEach(d -> System.out.println("  - " + d));

        assertEquals(EXPECTED, found);
    }
}