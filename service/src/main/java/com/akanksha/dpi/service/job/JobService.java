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
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

public class JobService {
    private static final Logger log = LoggerFactory.getLogger(JobService.class);

    private final AppClassifier classifier;
    private final ExecutorService executor;
    private final JobStore store;
    private final Path storageDir;
    private final int workers;

    public JobService(AppClassifier classifier, ExecutorService executor, JobStore store,
                      Path storageDir, int workers) throws IOException {
        if (workers < 1) throw new IllegalArgumentException("workers must be at least 1");
        this.classifier = classifier;
        this.executor = executor;
        this.store = store;
        this.storageDir = storageDir.toAbsolutePath().normalize();
        this.workers = workers;
        Files.createDirectories(this.storageDir);
    }

    /** Runs once at startup: jobs that were mid-flight when the service stopped can never finish. */
    public void recoverInterruptedJobs() {
        List<String> ids = store.failInterrupted("The service restarted before this analysis finished");
        for (String id : ids) {
            deleteQuietly(inputPath(id));
            deleteQuietly(outputPath(id));
        }
        if (!ids.isEmpty()) {
            log.warn("Marked {} interrupted job(s) as FAILED", ids.size());
        }
    }

    /** Saves the upload, checks that it is a PCAP file, and queues the analysis. Returns immediately. */
    public AnalysisJob submit(String originalName, InputStream data, RuleSpec rules) throws IOException {
        String id = UUID.randomUUID().toString();
        Path input = inputPath(id);

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

        AnalysisJob job = new AnalysisJob(id, safeName(originalName), rules);
        try {
            store.save(job);
        } catch (RuntimeException e) {
            deleteQuietly(input);
            throw e;
        }
        executor.execute(() -> run(job));
        return job;
    }

    public AnalysisJob get(String id) {
        return store.find(id).orElseThrow(() -> new JobNotFoundException(id));
    }

    public List<AnalysisJob> recent(int limit) {
        return store.recent(limit);
    }

    public Path outputFile(AnalysisJob job) {
        return outputPath(job.id());
    }

    public Path inputFile(AnalysisJob job) {
        return inputPath(job.id());
    }

    /** Deletes jobs that finished before the cutoff, together with their files. Returns how many. */
    public int deleteExpired(Instant cutoff) {
        List<String> ids = store.deleteFinishedBefore(cutoff);
        for (String id : ids) {
            deleteQuietly(outputPath(id));
            deleteQuietly(inputPath(id));
        }
        return ids.size();
    }

    private void run(AnalysisJob job) {
        job.markRunning();
        persist(job);
        try {
            AnalysisReport report = new DpiEngine(classifier, job.rules().toRules(), workers)
                    .process(inputPath(job.id()), outputPath(job.id()));
            deleteQuietly(inputPath(job.id()));      // cleanup happens before the status changes
            job.markCompleted(ReportData.from(report));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cleanupAfterFailure(job);
            job.markFailed("The analysis was interrupted");
        } catch (Exception e) {
            log.error("Job {} failed", job.id(), e);
            cleanupAfterFailure(job);
            job.markFailed(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        persist(job);
    }

    private void persist(AnalysisJob job) {
        try {
            store.save(job);
        } catch (RuntimeException e) {
            log.error("Could not save the state of job {}", job.id(), e);
        }
    }

    private void cleanupAfterFailure(AnalysisJob job) {
        deleteQuietly(inputPath(job.id()));
        deleteQuietly(outputPath(job.id()));
    }

    private Path inputPath(String id) {
        return storageDir.resolve(id + ".in.pcap");
    }

    private Path outputPath(String id) {
        return storageDir.resolve(id + ".out.pcap");
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