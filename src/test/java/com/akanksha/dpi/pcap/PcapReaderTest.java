package com.akanksha.dpi.pcap;

import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PcapReaderTest {

    @Test
    void readsAllPacketsFromSampleFile() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/test_dpi.pcap")) {
            assertNotNull(in, "test_dpi.pcap not found in src/test/resources");
            try (PcapReader reader = new PcapReader(in)) {
                int count = 0;
                long bytes = 0;
                while (true) {
                    var p = reader.readNext();
                    if (p.isEmpty()) break;
                    count++;
                    bytes += p.get().data().length;
                }
                System.out.println("Version: " + reader.getVersionMajor() + "." + reader.getVersionMinor()
                        + ", Snaplen: " + reader.getSnaplen()
                        + ", Link type: " + reader.getNetwork());
                System.out.println("Packets: " + count + ", Bytes: " + bytes);

                assertEquals(77, count);
                assertEquals(5738, bytes);
            }
        }
    }
}