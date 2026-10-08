package com.akanksha.dpi.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class PcapReader implements Closeable {
    private static final long MAGIC = 0xa1b2c3d4L;
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private static final long MAX_PACKET_LEN = 65535;

    private final InputStream in;
    private final ByteOrder order;
    private final int versionMajor;
    private final int versionMinor;
    private final long snaplen;
    private final long network;

    public PcapReader(InputStream stream) throws IOException {
        this.in = new BufferedInputStream(stream);

        byte[] hdr = in.readNBytes(GLOBAL_HEADER_SIZE);
        if (hdr.length < GLOBAL_HEADER_SIZE) {
            throw new IOException("File too short to be a PCAP file");
        }

        // Java has no unsigned ints: "& 0xFFFFFFFFL" turns a signed int into its unsigned value.
        ByteBuffer buf = ByteBuffer.wrap(hdr);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        if ((buf.getInt(0) & 0xFFFFFFFFL) == MAGIC) {
            this.order = ByteOrder.LITTLE_ENDIAN;
        } else {
            buf.order(ByteOrder.BIG_ENDIAN);
            if ((buf.getInt(0) & 0xFFFFFFFFL) == MAGIC) {
                this.order = ByteOrder.BIG_ENDIAN;
            } else {
                throw new IOException(String.format("Invalid PCAP magic number: 0x%08x", buf.getInt(0)));
            }
        }

        buf.order(this.order);
        this.versionMajor = buf.getShort(4) & 0xFFFF;
        this.versionMinor = buf.getShort(6) & 0xFFFF;
        this.snaplen = buf.getInt(16) & 0xFFFFFFFFL;
        this.network = buf.getInt(20) & 0xFFFFFFFFL;
    }

    public static PcapReader open(Path path) throws IOException {
        InputStream s = Files.newInputStream(path);
        try {
            return new PcapReader(s);
        } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
        }
    }

    /** Returns the next packet, or Optional.empty() at the end of the file. */
    public Optional<RawPacket> readNext() throws IOException {
        byte[] h = in.readNBytes(PACKET_HEADER_SIZE);
        if (h.length == 0) {
            return Optional.empty();
        }
        if (h.length < PACKET_HEADER_SIZE) {
            throw new IOException("Truncated packet header");
        }

        ByteBuffer b = ByteBuffer.wrap(h).order(order);
        long tsSec = b.getInt(0) & 0xFFFFFFFFL;
        long tsUsec = b.getInt(4) & 0xFFFFFFFFL;
        long inclLen = b.getInt(8) & 0xFFFFFFFFL;
        long origLen = b.getInt(12) & 0xFFFFFFFFL;

        if (inclLen > snaplen || inclLen > MAX_PACKET_LEN) {
            throw new IOException("Invalid packet length: " + inclLen);
        }

        byte[] data = in.readNBytes((int) inclLen);
        if (data.length < inclLen) {
            throw new IOException("Truncated packet data");
        }
        return Optional.of(new RawPacket(tsSec, tsUsec, origLen, data));
    }

    public int getVersionMajor() { return versionMajor; }
    public int getVersionMinor() { return versionMinor; }
    public long getSnaplen() { return snaplen; }
    public long getNetwork() { return network; }

    @Override
    public void close() throws IOException {
        in.close();
    }
}