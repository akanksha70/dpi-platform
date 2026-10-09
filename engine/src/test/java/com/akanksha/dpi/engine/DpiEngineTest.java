package com.akanksha.dpi.engine;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.model.AppType;
import com.akanksha.dpi.pcap.PcapReader;
import com.akanksha.dpi.pcap.RawPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DpiEngineTest {

    private static final Map<String, AppType> EXPECTED = Map.ofEntries(
            Map.entry("httpbin.org", AppType.HTTPS),
            Map.entry("example.com", AppType.HTTPS),
            Map.entry("www.youtube.com", AppType.YOUTUBE),
            Map.entry("www.facebook.com", AppType.FACEBOOK),
            Map.entry("www.microsoft.com", AppType.MICROSOFT),
            Map.entry("github.com", AppType.GITHUB),
            Map.entry("www.instagram.com", AppType.INSTAGRAM),
            Map.entry("discord.com", AppType.DISCORD),
            Map.entry("web.telegram.org", AppType.TELEGRAM),
            Map.entry("www.apple.com", AppType.APPLE),
            Map.entry("twitter.com", AppType.TWITTER),
            Map.entry("open.spotify.com", AppType.SPOTIFY),
            Map.entry("www.google.com", AppType.GOOGLE),
            Map.entry("www.amazon.com", AppType.AMAZON),
            Map.entry("zoom.us", AppType.ZOOM),
            Map.entry("www.cloudflare.com", AppType.CLOUDFLARE),
            Map.entry("www.netflix.com", AppType.NETFLIX),
            Map.entry("www.tiktok.com", AppType.TIKTOK));

    private Path sample() throws Exception {
        return Path.of(getClass().getResource("/test_dpi.pcap").toURI());
    }

    private AnalysisReport run(Path out, int workers, Rules rules) throws Exception {
        return new DpiEngine(AppClassifier.loadDefault(), rules, workers).process(sample(), out);
    }

    private List<RawPacket> readAll(Path file) throws Exception {
        List<RawPacket> list = new ArrayList<>();
        try (PcapReader reader = PcapReader.open(file)) {
            while (true) {
                var p = reader.readNext();
                if (p.isEmpty()) break;
                list.add(p.get());
            }
        }
        return list;
    }

    private FlowSummary flowFor(AnalysisReport r, String sni) {
        return r.flows().stream().filter(f -> sni.equals(f.sni())).findFirst().orElseThrow();
    }

    @Test
    void processesTheSampleLikeTheCppBaseline(@TempDir Path tmp) throws Exception {
        AnalysisReport r = run(tmp.resolve("out.pcap"), 4, new Rules());
        System.out.println(ReportFormatter.format(r));

        assertEquals(77, r.totalPackets());
        assertEquals(5738, r.totalBytes());
        assertEquals(73, r.tcpPackets());
        assertEquals(4, r.udpPackets());
        assertEquals(0, r.skippedPackets());
        assertEquals(77, r.forwarded());
        assertEquals(0, r.dropped());
        assertEquals(0, r.errors());
        assertEquals(77, Arrays.stream(r.processedPerWorker()).sum());
        assertEquals(77, r.appCounts().values().stream().mapToLong(Long::longValue).sum());
        assertEquals(EXPECTED, r.detectedSnis());
    }

    @Test
    void outputKeepsEveryPacketInTheOriginalOrder(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("out.pcap");
        run(out, 4, new Rules());

        List<RawPacket> in = readAll(sample());
        List<RawPacket> res = readAll(out);
        assertEquals(in.size(), res.size());
        for (int i = 0; i < in.size(); i++) {
            assertArrayEquals(in.get(i).data(), res.get(i).data(), "packet " + i);
            assertEquals(in.get(i).tsSec(), res.get(i).tsSec(), "timestamp of packet " + i);
            assertEquals(in.get(i).tsUsec(), res.get(i).tsUsec(), "microseconds of packet " + i);
            assertEquals(in.get(i).origLen(), res.get(i).origLen(), "original length of packet " + i);
        }
    }

    @Test
    void blockingTwitterDropsTwitterButNotNetflixOrMicrosoft(@TempDir Path tmp) throws Exception {
        Rules rules = new Rules();
        rules.blockApp("Twitter/X");
        Path out = tmp.resolve("out.pcap");
        AnalysisReport r = run(out, 4, rules);

        FlowSummary twitter = flowFor(r, "twitter.com");
        assertTrue(twitter.blocked());
        assertTrue(twitter.droppedPackets() > 0);

        for (String domain : new String[]{"www.netflix.com", "www.microsoft.com"}) {
            FlowSummary f = flowFor(r, domain);
            assertFalse(f.blocked(), domain + " must not be blocked");
            assertEquals(0, f.droppedPackets(), domain);
        }

        assertEquals(77, r.forwarded() + r.dropped());
        assertEquals(r.dropped(), r.flows().stream().mapToLong(FlowSummary::droppedPackets).sum());
        assertEquals(r.forwarded(), readAll(out).size());
    }

    @Test
    void workerCountDoesNotChangeTheResults(@TempDir Path tmp) throws Exception {
        AnalysisReport one = run(tmp.resolve("a.pcap"), 1, new Rules());
        AnalysisReport eight = run(tmp.resolve("b.pcap"), 8, new Rules());

        assertEquals(one.appCounts(), eight.appCounts());
        assertEquals(one.detectedSnis(), eight.detectedSnis());
        assertEquals(one.forwarded(), eight.forwarded());
        assertEquals(one.dropped(), eight.dropped());
    }
}