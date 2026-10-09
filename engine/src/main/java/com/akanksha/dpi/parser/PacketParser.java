package com.akanksha.dpi.parser;

import com.akanksha.dpi.pcap.RawPacket;

import java.util.Optional;

public final class PacketParser {
    public static final int ETHER_TYPE_IPV4 = 0x0800;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    private static final int ETH_HEADER_LEN = 14;
    private static final int MIN_IP_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {}

    /** Returns empty if the packet is malformed or too short (the C++ version returns false). */
    public static Optional<ParsedPacket> parse(RawPacket raw) {
        byte[] d = raw.data();
        int len = d.length;

        // ---- Ethernet (14 bytes) ----
        if (len < ETH_HEADER_LEN) return Optional.empty();
        String destMac = mac(d, 0);
        String srcMac = mac(d, 6);
        int etherType = u16(d, 12);
        int offset = ETH_HEADER_LEN;

        boolean hasIp = false, hasTcp = false, hasUdp = false;
        int ipVersion = 0, protocol = 0, ttl = 0, srcPort = 0, destPort = 0, tcpFlags = 0;
        String srcIp = "", destIp = "";
        long seq = 0, ack = 0;

        if (etherType == ETHER_TYPE_IPV4) {
            // ---- IPv4 (20 to 60 bytes) ----
            if (len < offset + MIN_IP_HEADER_LEN) return Optional.empty();
            int versionIhl = u8(d, offset);
            ipVersion = (versionIhl >> 4) & 0x0F;   // top 4 bits
            int ihl = versionIhl & 0x0F;            // bottom 4 bits, counted in 4-byte words
            if (ipVersion != 4) return Optional.empty();
            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset + ipHeaderLen) return Optional.empty();

            ttl = u8(d, offset + 8);
            protocol = u8(d, offset + 9);
            srcIp = ip(d, offset + 12);
            destIp = ip(d, offset + 16);
            hasIp = true;
            offset += ipHeaderLen;

            if (protocol == PROTO_TCP) {
                // ---- TCP (20 to 60 bytes) ----
                if (len < offset + MIN_TCP_HEADER_LEN) return Optional.empty();
                srcPort = u16(d, offset);
                destPort = u16(d, offset + 2);
                seq = u32(d, offset + 4);
                ack = u32(d, offset + 8);
                int tcpHeaderLen = ((u8(d, offset + 12) >> 4) & 0x0F) * 4;
                tcpFlags = u8(d, offset + 13);
                if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset + tcpHeaderLen) return Optional.empty();
                hasTcp = true;
                offset += tcpHeaderLen;
            } else if (protocol == PROTO_UDP) {
                // ---- UDP (always 8 bytes) ----
                if (len < offset + UDP_HEADER_LEN) return Optional.empty();
                srcPort = u16(d, offset);
                destPort = u16(d, offset + 2);
                hasUdp = true;
                offset += UDP_HEADER_LEN;
            }
        }

        int payloadLength = offset < len ? len - offset : 0;

        return Optional.of(new ParsedPacket(
                raw.tsSec(), raw.tsUsec(),
                srcMac, destMac, etherType,
                hasIp, ipVersion, srcIp, destIp, protocol, ttl,
                hasTcp, hasUdp, srcPort, destPort,
                tcpFlags, seq, ack,
                offset, payloadLength));
    }

    // ---- Helpers. Java bytes are signed (-128..127), so "& 0xFF" converts to 0..255. ----

    static int u8(byte[] d, int i) {
        return d[i] & 0xFF;
    }

    /** Reads 2 bytes in network order (big-endian: first byte is the high part). */
    static int u16(byte[] d, int i) {
        return (u8(d, i) << 8) | u8(d, i + 1);
    }

    /** Reads 4 bytes in network order. Returns long because int cannot hold values above 2^31. */
    static long u32(byte[] d, int i) {
        return ((long) u8(d, i) << 24) | ((long) u8(d, i + 1) << 16)
                | ((long) u8(d, i + 2) << 8) | (long) u8(d, i + 3);
    }

    static String mac(byte[] d, int i) {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < 6; k++) {
            if (k > 0) sb.append(':');
            sb.append(String.format("%02x", u8(d, i + k)));
        }
        return sb.toString();
    }

    static String ip(byte[] d, int i) {
        return u8(d, i) + "." + u8(d, i + 1) + "." + u8(d, i + 2) + "." + u8(d, i + 3);
    }
}