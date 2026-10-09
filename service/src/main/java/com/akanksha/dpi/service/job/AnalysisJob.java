package com.akanksha.dpi.service.job;

import com.akanksha.dpi.engine.AnalysisReport;

import java.nio.file.Path;
import java.time.Instant;

/**
 * One analysis request. The mutable fields are volatile because the job thread writes them
 * while HTTP threads read them. Status is always written last, so a reader that sees
 * COMPLETED also sees the report.
 */
public final class AnalysisJob {
    private final String id;
    private final String displayName;
    private final RuleSpec rules;
    private final Path inputPath;
    private final Path outputPath;
    private final Instant createdAt = Instant.now();

    private volatile JobStatus status = JobStatus.QUEUED;
    private volatile Instant startedAt;
    private volatile Instant finishedAt;
    private volatile String error;
    private volatile AnalysisReport report;

    AnalysisJob(String id, String displayName, RuleSpec rules, Path inputPath, Path outputPath) {
        this.id = id;
        this.displayName = displayName;
        this.rules = rules;
        this.inputPath = inputPath;
        this.outputPath = outputPath;
    }

    public String id() { return id; }
    public String displayName() { return displayName; }
    public RuleSpec rules() { return rules; }
    public Path inputPath() { return inputPath; }
    public Path outputPath() { return outputPath; }
    public Instant createdAt() { return createdAt; }
    public JobStatus status() { return status; }
    public Instant startedAt() { return startedAt; }
    public Instant finishedAt() { return finishedAt; }
    public String error() { return error; }
    public AnalysisReport report() { return report; }

    void markRunning() {
        startedAt = Instant.now();
        status = JobStatus.RUNNING;
    }

    void markCompleted(AnalysisReport result) {
        report = result;
        finishedAt = Instant.now();
        status = JobStatus.COMPLETED;
    }

    void markFailed(String message) {
        error = message;
        finishedAt = Instant.now();
        status = JobStatus.FAILED;
    }
}