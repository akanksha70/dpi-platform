package com.akanksha.dpi.service.job;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** One row of the analysis_job table. */
@Entity
@Table(name = "analysis_job")
public class JobRecord {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "status", nullable = false, length = 20)
    private String status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(name = "error")
    private String error;

    @Column(name = "rules_json", nullable = false)
    private String rulesJson;

    @Column(name = "report_json")
    private String reportJson;

    protected JobRecord() {
        // required by JPA
    }

    static JobRecord from(AnalysisJob job, String rulesJson, String reportJson) {
        JobRecord r = new JobRecord();
        r.id = job.id();
        r.fileName = job.displayName();
        r.status = job.status().name();
        r.createdAt = job.createdAt();
        r.startedAt = job.startedAt();
        r.finishedAt = job.finishedAt();
        r.error = truncate(job.error());
        r.rulesJson = rulesJson;
        r.reportJson = reportJson;
        return r;
    }

    void markFailed(String reason, Instant at) {
        this.status = JobStatus.FAILED.name();
        this.error = truncate(reason);
        this.finishedAt = at;
    }

    private static String truncate(String s) {
        return s == null || s.length() <= 1000 ? s : s.substring(0, 1000);
    }

    public String getId() { return id; }
    public String getFileName() { return fileName; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getStartedAt() { return startedAt; }
    public Instant getFinishedAt() { return finishedAt; }
    public String getError() { return error; }
    public String getRulesJson() { return rulesJson; }
    public String getReportJson() { return reportJson; }
}