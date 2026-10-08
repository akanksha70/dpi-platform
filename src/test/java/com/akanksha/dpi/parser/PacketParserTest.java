package com.akanksha.dpi.parser;

import com.akanksha.dpi.pcap.PcapReader;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PacketParserTest {

    @Test
    void parsesSampleFileLikeTheCppBaseline() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/test_dpi.pcap")) {
            assertNotNull(in, "test_dpi.pcap not found in src/test/resources");
            try (PcapReader reader = new PcapReader(in)) {
                int accepted = 0, tcp = 0, udp = 0, shown = 0;
                long bytes = 0;

                while (true) {
                    var raw = reader.readNext();
                    if (raw.isEmpty()) break;

                    var parsed = PacketParser.parse(raw.get());
                    if (parsed.isEmpty()) continue;

                    ParsedPacket p = parsed.get();
                    if (!p.hasIp() || (!p.hasTcp() && !p.hasUdp())) continue;

                    accepted++;
                    bytes += raw.get().data().length;
                    if (p.hasTcp()) tcp++;
                    else udp++;

                    if (shown < 5) {
                        System.out.println(p.srcIp() + ":" + p.srcPort() + " -> "
                                + p.destIp() + ":" + p.destPort()
                                + " proto=" + p.protocol() + " flags=0x" + Integer.toHexString(p.tcpFlags())
                                + " payload=" + p.payloadLength());
                        shown++;
                    }
                }
                System.out.println("Accepted: " + accepted + ", TCP: " + tcp + ", UDP: " + udp + ", Bytes: " + bytes);

                assertEquals(77, accepted);
                assertEquals(73, tcp);
                assertEquals(4, udp);
                assertEquals(5738, bytes);
            }
        }
    }
}