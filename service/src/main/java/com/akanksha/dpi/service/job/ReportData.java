package com.akanksha.dpi.service.job;

import com.akanksha.dpi.engine.AnalysisReport;
import com.akanksha.dpi.engine.FlowSummary;

import java.util.Arrays;
import java.util.List;

/**
 * The finished report in the shape that is both stored in the database and returned by the API.
 * Lists are capped so a huge capture cannot produce a report that is too big to store.
 */
public record ReportData(
        long totalPackets, long totalBytes, long tcpPackets, long udpPackets, long skippedPackets,
        long forwarded, long dropped, long errors,
        List<Long> packetsPerWorker,
        List<AppCount> apps,
        List<DomainView> domains,
        List<FlowView> flows,
        int totalDomains, int totalFlows, boolean truncated) {

    public static final int MAX_LISTED = 1000;

    public record AppCount(String app, long packets) {}

    public record DomainView(String domain, String app) {}

    /** A flow covers both directions of a connection, so A and B are just the two endpoints. */
    public record FlowView(String ipA, int portA, String ipB, int portB, String protocol,
                           String app, String sni, long packets, long bytes,
                           long droppedPackets, boolean blocked) {}

    public static ReportData from(AnalysisReport r) {
        List<AppCount> apps = r.appCounts().entrySet().stream()
                .sorted((a, b) -> {
                    int c = Long.compare(b.getValue(), a.getValue());
                    return c != 0 ? c : a.getKey().displayName().compareTo(b.getKey().displayName());
                })
                .map(e -> new AppCount(e.getKey().displayName(), e.getValue()))
                .toList();

        List<DomainView> allDomains = r.detectedSnis().entrySet().stream()
                .map(e -> new DomainView(e.getKey(), e.getValue().displayName()))
                .toList();

        List<FlowView> allFlows = r.flows().stream()
                .sorted((a, b) -> {
                    int c = Long.compare(b.packets(), a.packets());
                    return c != 0 ? c : a.key().toString().compareTo(b.key().toString());
                })
                .map(ReportData::flow)
                .toList();

        boolean truncated = allDomains.size() > MAX_LISTED || allFlows.size() > MAX_LISTED;

        return new ReportData(
                r.totalPackets(), r.totalBytes(), r.tcpPackets(), r.udpPackets(), r.skippedPackets(),
                r.forwarded(), r.dropped(), r.errors(),
                Arrays.stream(r.processedPerWorker()).boxed().toList(),
                apps,
                List.copyOf(allDomains.subList(0, Math.min(allDomains.size(), MAX_LISTED))),
                List.copyOf(allFlows.subList(0, Math.min(allFlows.size(), MAX_LISTED))),
                allDomains.size(), allFlows.size(), truncated);
    }

    private static FlowView flow(FlowSummary f) {
        var k = f.key();
        return new FlowView(k.srcIp(), k.srcPort(), k.dstIp(), k.dstPort(), protocolName(k.protocol()),
                f.app().displayName(), f.sni(), f.packets(), f.bytes(), f.droppedPackets(), f.blocked());
    }

    private static String protocolName(int protocol) {
        return protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : String.valueOf(protocol);
    }
}