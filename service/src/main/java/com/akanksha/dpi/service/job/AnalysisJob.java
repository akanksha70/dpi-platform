package com.akanksha.dpi.service.job;

import java.time.Instant;

/**
 * One analysis request. The mutable fields are volatile because the job thread writes them
 * while HTTP threads read them. Status is always written last, so a reader that sees
 * COMPLETED also sees the report. File locations are not stored here: they follow from the id.
 */
public final class AnalysisJob {
    private final String id;
    private final String displayName;
    private final RuleSpec rules;
    private final Instant createdAt;

    private volatile JobStatus status = JobStatus.QUEUED;
    private volatile Instant startedAt;
    private volatile Instant finishedAt;
    private volatile String error;
    private volatile ReportData report;

    AnalysisJob(String id, String displayName, RuleSpec rules) {
        this(id, displayName, rules, Instant.now());
    }

    private AnalysisJob(String id, String displayName, RuleSpec rules, Instant createdAt) {
        this.id = id;
        this.displayName = displayName;
        this.rules = rules;
        this.createdAt = createdAt;
    }

    /** Rebuilds a job that was loaded from storage. */
    static AnalysisJob restore(String id, String displayName, RuleSpec rules, Instant createdAt,
                               JobStatus status, Instant startedAt, Instant finishedAt,
                               String error, ReportData report) {
        AnalysisJob job = new AnalysisJob(id, displayName, rules, createdAt);
        job.startedAt = startedAt;
        job.finishedAt = finishedAt;
        job.error = error;
        job.report = report;
        job.status = status;
        return job;
    }

    public String id() { return id; }
    public String displayName() { return displayName; }
    public RuleSpec rules() { return rules; }
    public Instant createdAt() { return createdAt; }
    public JobStatus status() { return status; }
    public Instant startedAt() { return startedAt; }
    public Instant finishedAt() { return finishedAt; }
    public String error() { return error; }
    public ReportData report() { return report; }

    void markRunning() {
        startedAt = Instant.now();
        status = JobStatus.RUNNING;
    }

    void markCompleted(ReportData result) {
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