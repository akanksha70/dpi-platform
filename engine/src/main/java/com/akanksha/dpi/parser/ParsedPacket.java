
package com.akanksha.dpi.parser;

public record ParsedPacket(
        long tsSec, long tsUsec,
        String srcMac, String destMac, int etherType,
        boolean hasIp, int ipVersion, String srcIp, String destIp, int protocol, int ttl,
        boolean hasTcp, boolean hasUdp, int srcPort, int destPort,
        int tcpFlags, long seqNumber, long ackNumber,
        int payloadOffset, int payloadLength) {}