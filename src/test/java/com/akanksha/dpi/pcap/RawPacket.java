package com.akanksha.dpi.pcap;

public record RawPacket(long tsSec, long tsUsec, long origLen, byte[] data) {}