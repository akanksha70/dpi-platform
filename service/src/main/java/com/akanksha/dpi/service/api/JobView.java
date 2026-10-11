package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.job.AnalysisJob;
import com.akanksha.dpi.service.job.JobStatus;
import com.akanksha.dpi.service.job.ReportData;
import com.akanksha.dpi.service.job.RuleSpec;

import java.time.Instant;

public record JobView(String id, String status, String fileName, Instant createdAt, Instant startedAt,
                      Instant finishedAt, String error, RuleSpec rules, Summary summary) {

    public record Summary(long totalPackets, long forwarded, long dropped, long errors) {}

    /** Full view, including the summary of a finished analysis. */
    public static JobView of(AnalysisJob job) {
        return build(job, true);
    }

    /** List entries leave the summary out, so listing many jobs never has to load their reports. */
    public static JobView listItem(AnalysisJob job) {
        return build(job, false);
    }

    private static JobView build(AnalysisJob job, boolean withSummary) {
        JobStatus status = job.status();   // read once, so all fields below belong to the same moment
        ReportData r = job.report();
        Summary summary = (withSummary && status == JobStatus.COMPLETED && r != null)
                ? new Summary(r.totalPackets(), r.forwarded(), r.dropped(), r.errors())
                : null;
        return new JobView(job.id(), status.name(), job.displayName(), job.createdAt(), job.startedAt(),
                job.finishedAt(), job.error(), job.rules(), summary);
    }
}