package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.AppType;

import java.util.List;
import java.util.Map;

public record AnalysisReport(
        long totalPackets, long totalBytes, long tcpPackets, long udpPackets, long skippedPackets,
        long forwarded, long dropped, long errors,
        long[] processedPerWorker,
        Map<AppType, Long> appCounts,
        Map<String, AppType> detectedSnis,
        List<FlowSummary> flows) {}