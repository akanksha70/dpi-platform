package com.akanksha.dpi.engine;

import com.akanksha.dpi.pcap.RawPacket;

/** A worker's decision for one packet. END tells the writer that everything has been delivered. */
record PacketResult(long seq, RawPacket raw, boolean forward) {
    static final PacketResult END = new PacketResult(-1, null, false);
}