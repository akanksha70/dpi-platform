package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.FiveTuple;
import com.akanksha.dpi.parser.ParsedPacket;
import com.akanksha.dpi.pcap.RawPacket;

/** One packet on its way to a worker. POISON is the "no more packets" stop marker. */
record PacketJob(long seq, RawPacket raw, ParsedPacket parsed, FiveTuple key) {
    static final PacketJob POISON = new PacketJob(-1, null, null, null);
}