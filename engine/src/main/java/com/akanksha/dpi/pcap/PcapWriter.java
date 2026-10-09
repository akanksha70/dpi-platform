package com.akanksha.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Writes packets to a .pcap file (always little-endian, which every tool understands). */
public class PcapWriter implements Closeable {
    private final OutputStream out;

    public PcapWriter(OutputStream stream, long snaplen, long network) throws IOException {
        this.out = new BufferedOutputStream(stream);
        ByteBuffer b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) 0xa1b2c3d4L);   // magic number; the (int) cast keeps the same 32 bits
        b.putShort((short) 2);          // version 2.4
        b.putShort((short) 4);
        b.putInt(0);                    // timezone offset
        b.putInt(0);                    // timestamp accuracy
        b.putInt((int) snaplen);
        b.putInt((int) network);
        out.write(b.array());
    }

    public static PcapWriter create(Path path, long snaplen, long network) throws IOException {
        OutputStream s = Files.newOutputStream(path);
        try {
            return new PcapWriter(s, snaplen, network);
        } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
        }
    }

    public void write(RawPacket p) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt((int) p.tsSec());
        b.putInt((int) p.tsUsec());
        b.putInt(p.data().length);       // bytes stored in the file
        b.putInt((int) p.origLen());     // original length (the C++ version overwrote this)
        out.write(b.array());
        out.write(p.data());
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}