package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.AppType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class ReportFormatter {
    private ReportFormatter() {}

    public static String format(AnalysisReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("==================== PROCESSING REPORT ====================\n");
        row(sb, "Total packets", r.totalPackets());
        row(sb, "Total bytes", r.totalBytes());
        row(sb, "TCP packets", r.tcpPackets());
        row(sb, "UDP packets", r.udpPackets());
        row(sb, "Skipped (not IP/TCP/UDP)", r.skippedPackets());
        sb.append("-----------------------------------------------------------\n");
        row(sb, "Forwarded", r.forwarded());
        row(sb, "Dropped", r.dropped());
        row(sb, "Internal errors", r.errors());
        sb.append("-----------------------------------------------------------\n");
        sb.append("WORKER STATISTICS\n");
        for (int i = 0; i < r.processedPerWorker().length; i++) {
            row(sb, "  Worker " + i + " processed", r.processedPerWorker()[i]);
        }
        sb.append("-----------------------------------------------------------\n");
        sb.append("APPLICATION BREAKDOWN (packets)\n");

        List<Map.Entry<AppType, Long>> entries = new ArrayList<>(r.appCounts().entrySet());
        entries.sort((a, b) -> {
            int c = Long.compare(b.getValue(), a.getValue());
            return c != 0 ? c : a.getKey().displayName().compareTo(b.getKey().displayName());
        });
        for (Map.Entry<AppType, Long> e : entries) {
            double pct = r.totalPackets() > 0 ? 100.0 * e.getValue() / r.totalPackets() : 0;
            sb.append(String.format("  %-12s %6d %6.1f%%  %s%n",
                    e.getKey().displayName(), e.getValue(), pct, "#".repeat((int) (pct / 5))));
        }

        if (!r.detectedSnis().isEmpty()) {
            sb.append("-----------------------------------------------------------\n");
            sb.append("DETECTED DOMAINS\n");
            r.detectedSnis().forEach((sni, app) ->
                    sb.append("  - ").append(sni).append(" -> ").append(app.displayName()).append('\n'));
        }
        return sb.toString();
    }

    private static void row(StringBuilder sb, String label, long value) {
        sb.append(String.format("  %-26s %10d%n", label, value));
    }
}