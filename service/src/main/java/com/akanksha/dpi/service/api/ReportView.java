package com.akanksha.dpi.service.api;

import com.akanksha.dpi.engine.AnalysisReport;
import com.akanksha.dpi.engine.FlowSummary;

import java.util.Arrays;
import java.util.List;

/** The public JSON shape of a report. Kept separate from the engine's own types on purpose. */
public record ReportView(
        String jobId,
        long totalPackets, long totalBytes, long tcpPackets, long udpPackets, long skippedPackets,
        long forwarded, long dropped, long errors,
        List<Long> packetsPerWorker,
        List<AppCount> apps,
        List<DomainView> domains,
        List<FlowView> flows) {

    public record AppCount(String app, long packets) {}

    public record DomainView(String domain, String app) {}

    /** A flow covers both directions of a connection, so A and B are just the two endpoints. */
    public record FlowView(String ipA, int portA, String ipB, int portB, String protocol,
                           String app, String sni, long packets, long bytes,
                           long droppedPackets, boolean blocked) {}

    public static ReportView of(String jobId, AnalysisReport r) {
        List<AppCount> apps = r.appCounts().entrySet().stream()
                .sorted((a, b) -> {
                    int c = Long.compare(b.getValue(), a.getValue());
                    return c != 0 ? c : a.getKey().displayName().compareTo(b.getKey().displayName());
                })
                .map(e -> new AppCount(e.getKey().displayName(), e.getValue()))
                .toList();

        List<DomainView> domains = r.detectedSnis().entrySet().stream()
                .map(e -> new DomainView(e.getKey(), e.getValue().displayName()))
                .toList();

        List<FlowView> flows = r.flows().stream().map(ReportView::flow).toList();

        return new ReportView(jobId,
                r.totalPackets(), r.totalBytes(), r.tcpPackets(), r.udpPackets(), r.skippedPackets(),
                r.forwarded(), r.dropped(), r.errors(),
                Arrays.stream(r.processedPerWorker()).boxed().toList(),
                apps, domains, flows);
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