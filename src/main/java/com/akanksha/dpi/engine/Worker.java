package com.akanksha.dpi.engine;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.model.AppType;
import com.akanksha.dpi.model.FiveTuple;
import com.akanksha.dpi.parser.ParsedPacket;
import com.akanksha.dpi.sni.HttpHostExtractor;
import com.akanksha.dpi.sni.SniExtractor;

import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;

/**
 * One worker thread. It owns its flow table and counters, so no locks are needed:
 * the main thread only reads them after the worker has finished (Thread.join).
 */
final class Worker implements Runnable {
    private final BlockingQueue<PacketJob> input;
    private final BlockingQueue<PacketResult> output;
    private final Rules rules;
    private final AppClassifier classifier;

    private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();
    long processed, forwarded, dropped, errors;
    final Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
    final Map<String, AppType> detectedSnis = new TreeMap<>();

    Worker(BlockingQueue<PacketJob> input, BlockingQueue<PacketResult> output,
           Rules rules, AppClassifier classifier) {
        this.input = input;
        this.output = output;
        this.rules = rules;
        this.classifier = classifier;
    }

    Collection<FlowEntry> flows() {
        return flows.values();
    }

    @Override
    public void run() {
        try {
            while (true) {
                PacketJob job = input.take();
                if (job == PacketJob.POISON) break;   // everything before the marker was already handled
                handle(job);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void handle(PacketJob job) {
        processed++;
        boolean forward = true;
        FlowEntry flow = null;
        try {
            ParsedPacket p = job.parsed();
            flow = flows.computeIfAbsent(job.key(), FlowEntry::new);
            flow.packets++;
            flow.bytes += job.raw().data().length;

            if (!flow.classified) classify(job, flow);

            if (!flow.blocked && rules.isBlocked(p.srcIp(), flow.app, flow.sni)) {
                flow.blocked = true;   // sticky: every later packet of this flow is dropped
            }

            appCounts.merge(flow.app, 1L, Long::sum);
            if (!flow.sni.isEmpty()) detectedSnis.put(flow.sni, flow.app);

            forward = !flow.blocked;
        } catch (RuntimeException e) {
            errors++;
            forward = true;            // fail-open: an internal error must not silently eat traffic
        }

        if (forward) {
            forwarded++;
        } else {
            dropped++;
            flow.droppedPackets++;
        }
        output.add(new PacketResult(job.seq(), job.raw(), forward));
    }

    private void classify(PacketJob job, FlowEntry flow) {
        ParsedPacket p = job.parsed();
        byte[] data = job.raw().data();

        if (p.destPort() == 443 && p.payloadLength() > 5) {
            Optional<String> sni = SniExtractor.extract(data, p.payloadOffset(), p.payloadLength());
            if (sni.isPresent()) {
                flow.sni = sni.get();
                flow.app = classifier.classify(flow.sni);
                flow.classified = true;
                return;
            }
        }
        if (p.destPort() == 80 && p.payloadLength() > 10) {
            Optional<String> host = HttpHostExtractor.extract(data, p.payloadOffset(), p.payloadLength());
            if (host.isPresent()) {
                flow.sni = host.get();
                flow.app = classifier.classify(flow.sni);
                flow.classified = true;
                return;
            }
        }
        if (p.destPort() == 53 || p.srcPort() == 53) {
            flow.app = AppType.DNS;
            flow.classified = true;
            return;
        }
        // Port-based guess; not marked as classified because an SNI may still arrive.
        if (p.destPort() == 443) {
            flow.app = AppType.HTTPS;
        } else if (p.destPort() == 80) {
            flow.app = AppType.HTTP;
        }
    }
}