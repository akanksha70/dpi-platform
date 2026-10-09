package com.akanksha.dpi.engine;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.model.AppType;
import com.akanksha.dpi.model.FiveTuple;
import com.akanksha.dpi.parser.PacketParser;
import com.akanksha.dpi.parser.ParsedPacket;
import com.akanksha.dpi.pcap.PcapReader;
import com.akanksha.dpi.pcap.PcapWriter;
import com.akanksha.dpi.pcap.RawPacket;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reader (this thread) -> N workers (hash-partitioned by flow) -> one ordered writer thread.
 */
public class DpiEngine {
    private static final int QUEUE_CAPACITY = 1024;

    private final AppClassifier classifier;
    private final Rules rules;
    private final int workerCount;

    public DpiEngine(AppClassifier classifier, Rules rules, int workerCount) {
        if (workerCount < 1) throw new IllegalArgumentException("workers must be at least 1");
        this.classifier = classifier;
        this.rules = rules;
        this.workerCount = workerCount;
    }

    public AnalysisReport process(Path input, Path output) throws IOException, InterruptedException {
        BlockingQueue<PacketResult> results = new LinkedBlockingQueue<>();   // unbounded: workers never block on it
        List<BlockingQueue<PacketJob>> queues = new ArrayList<>();
        List<Worker> workers = new ArrayList<>();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < workerCount; i++) {
            BlockingQueue<PacketJob> q = new ArrayBlockingQueue<>(QUEUE_CAPACITY);   // bounded: slows the reader down
            Worker w = new Worker(q, results, rules, classifier);
            queues.add(q);
            workers.add(w);
            threads.add(new Thread(w, "dpi-worker-" + i));
        }

        long total = 0, bytes = 0, tcp = 0, udp = 0, skipped = 0;
        AtomicReference<Throwable> writerFailure = new AtomicReference<>();

        try (PcapReader reader = PcapReader.open(input);
             PcapWriter writer = PcapWriter.create(output, reader.getSnaplen(), reader.getNetwork())) {

            Thread writerThread = new Thread(() -> writeInOrder(results, writer, writerFailure), "dpi-writer");
            writerThread.start();
            threads.forEach(Thread::start);

            try {
                long seq = 0;
                while (true) {
                    var rawOpt = reader.readNext();
                    if (rawOpt.isEmpty()) break;
                    RawPacket raw = rawOpt.get();

                    var parsedOpt = PacketParser.parse(raw);
                    if (parsedOpt.isEmpty()) { skipped++; continue; }
                    ParsedPacket p = parsedOpt.get();
                    if (!p.hasIp() || (!p.hasTcp() && !p.hasUdp())) { skipped++; continue; }

                    total++;
                    bytes += raw.data().length;
                    if (p.hasTcp()) tcp++; else udp++;

                    FiveTuple key = new FiveTuple(p.srcIp(), p.destIp(), p.srcPort(), p.destPort(), p.protocol())
                            .canonical();
                    int w = WorkerSelector.select(key, workerCount);
                    queues.get(w).put(new PacketJob(seq++, raw, p, key));   // blocks if that worker is busy
                }
            } finally {
                // Runs even if reading failed halfway, so no thread is left waiting forever.
                for (BlockingQueue<PacketJob> q : queues) q.put(PacketJob.POISON);
                for (Thread t : threads) t.join();       // wait until every queued packet has been handled
                results.put(PacketResult.END);
                writerThread.join();
            }

            Throwable failure = writerFailure.get();
            if (failure != null) throw new IOException("Writing the output file failed", failure);

            long forwarded = 0, dropped = 0, errors = 0;
            long[] perWorker = new long[workerCount];
            Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
            Map<String, AppType> snis = new TreeMap<>();
            List<FlowSummary> flows = new ArrayList<>();
            for (int i = 0; i < workerCount; i++) {
                Worker w = workers.get(i);
                perWorker[i] = w.processed;
                forwarded += w.forwarded;
                dropped += w.dropped;
                errors += w.errors;
                w.appCounts.forEach((app, n) -> appCounts.merge(app, n, Long::sum));
                snis.putAll(w.detectedSnis);
                for (FlowEntry f : w.flows()) flows.add(f.toSummary());
            }
            flows.sort(Comparator.comparing((FlowSummary f) -> f.key().toString()));

            return new AnalysisReport(total, bytes, tcp, udp, skipped, forwarded, dropped, errors,
                    perWorker, appCounts, snis, flows);
        }
    }

    /** Writes forwarded packets in their original order, even though workers finish out of order. */
    private static void writeInOrder(BlockingQueue<PacketResult> results, PcapWriter writer,
                                     AtomicReference<Throwable> failure) {
        PriorityQueue<PacketResult> pending = new PriorityQueue<>(Comparator.comparingLong(PacketResult::seq));
        long next = 0;
        boolean failed = false;
        try {
            while (true) {
                PacketResult r = results.take();
                if (r == PacketResult.END) break;
                if (failed) continue;        // keep draining so memory does not pile up
                try {
                    pending.add(r);
                    while (!pending.isEmpty() && pending.peek().seq() == next) {
                        PacketResult ready = pending.poll();
                        if (ready.forward()) writer.write(ready.raw());
                        next++;              // dropped packets advance the counter too
                    }
                } catch (IOException e) {
                    failure.set(e);
                    failed = true;
                }
            }
            // Safety net: if a sequence number never arrived, still write what is left, in order.
            while (!failed && !pending.isEmpty()) {
                PacketResult r = pending.poll();
                if (r.forward()) writer.write(r.raw());
            }
        } catch (IOException e) {
            failure.set(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            failure.set(e);
        }
    }
}