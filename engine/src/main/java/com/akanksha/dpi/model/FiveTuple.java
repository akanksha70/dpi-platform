package com.akanksha.dpi.model;

public record FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * Returns the same key for both directions of a connection, so client->server and
     * server->client packets land in the same flow (this fixes the one-direction blocking bug).
     */
    public FiveTuple canonical() {
        int cmp = srcIp.compareTo(dstIp);
        if (cmp == 0) cmp = Integer.compare(srcPort, dstPort);
        return cmp <= 0 ? this : reverse();
    }
}