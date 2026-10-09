package com.akanksha.dpi.service.job;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.engine.AnalysisReport;
import com.akanksha.dpi.engine.DpiEngine;
import com.akanksha.dpi.pcap.PcapReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

public class JobService {
    private static final Logger log = LoggerFactory.getLogger(JobService.class);

    private final AppClassifier classifier;
    private final ExecutorService executor;
    private final Path storageDir;
    private final int workers;
    private final Map<String, AnalysisJob> jobs = new ConcurrentHashMap<>();

    public JobService(AppClassifier classifier, ExecutorService executor, Path storageDir, int workers)
            throws IOException {
        if (workers < 1) throw new IllegalArgumentException("workers must be at least 1");
        this.classifier = classifier;
        this.executor = executor;
        this.storageDir = storageDir;
        this.workers = workers;
        Files.createDirectories(storageDir);
    }

    /** Saves the upload, checks that it is a PCAP file, and queues the analysis. Returns immediately. */
    public AnalysisJob submit(String originalName, InputStream data, RuleSpec rules) throws IOException {
        String id = UUID.randomUUID().toString();
        Path input = storageDir.resolve(id + ".in.pcap");
        Path output = storageDir.resolve(id + ".out.pcap");

        try {
            Files.copy(data, input);
        } catch (IOException | RuntimeException e) {
            deleteQuietly(input);
            throw e;
        }

        // Opening the file reads and validates the 24-byte PCAP header, so bad uploads fail right away.
        try (PcapReader ignored = PcapReader.open(input)) {
            log.debug("Accepted upload {} as job {}", originalName, id);
        } catch (IOException e) {
            deleteQuietly(input);
            throw new InvalidInputException("Not a valid PCAP file: " + e.getMessage());
        }

        AnalysisJob job = new AnalysisJob(id, safeName(originalName), rules, input, output);
        jobs.put(id, job);
        executor.execute(() -> run(job));
        return job;
    }

    public AnalysisJob get(String id) {
        AnalysisJob job = jobs.get(id);
        if (job == null) throw new JobNotFoundException(id);
        return job;
    }

    public List<AnalysisJob> recent(int limit) {
        return jobs.values().stream()
                .sorted(Comparator.comparing(AnalysisJob::createdAt).reversed())
                .limit(limit)
                .toList();
    }

    private void run(AnalysisJob job) {
        job.markRunning();
        try {
            AnalysisReport report = new DpiEngine(classifier, job.rules().toRules(), workers)
                    .process(job.inputPath(), job.outputPath());
            deleteQuietly(job.inputPath());          // cleanup happens before the status changes
            job.markCompleted(report);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cleanupAfterFailure(job);
            job.markFailed("The analysis was interrupted");
        } catch (Exception e) {
            log.error("Job {} failed", job.id(), e);
            cleanupAfterFailure(job);
            job.markFailed(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    private void cleanupAfterFailure(AnalysisJob job) {
        deleteQuietly(job.inputPath());
        deleteQuietly(job.outputPath());
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("Could not delete {}", path, e);
        }
    }

    /** Keeps only the file name part and replaces odd characters, because it ends up in a download header. */
    public static String safeName(String name) {
        if (name == null || name.isBlank()) return "capture.pcap";
        String base = name.replace('\\', '/');
        base = base.substring(base.lastIndexOf('/') + 1);
        base = base.replaceAll("[^A-Za-z0-9._-]", "_");
        if (base.length() > 100) base = base.substring(base.length() - 100);
        return base.isEmpty() ? "capture.pcap" : base;
    }
}