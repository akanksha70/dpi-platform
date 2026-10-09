package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.AppType;
import com.akanksha.dpi.model.FiveTuple;

/** Mutable state of one connection. Only one worker thread ever touches a given FlowEntry. */
final class FlowEntry {
    final FiveTuple key;
    AppType app = AppType.UNKNOWN;
    String sni = "";
    long packets;
    long bytes;
    long droppedPackets;
    boolean blocked;
    boolean classified;

    FlowEntry(FiveTuple key) {
        this.key = key;
    }

    FlowSummary toSummary() {
        return new FlowSummary(key, app, sni, packets, bytes, droppedPackets, blocked);
    }
}