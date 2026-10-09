package com.akanksha.dpi.service.api;

import com.akanksha.dpi.engine.AnalysisReport;
import com.akanksha.dpi.service.job.AnalysisJob;
import com.akanksha.dpi.service.job.JobStatus;
import com.akanksha.dpi.service.job.RuleSpec;

import java.time.Instant;

public record JobView(String id, String status, String fileName, Instant createdAt, Instant startedAt,
                      Instant finishedAt, String error, RuleSpec rules, Summary summary) {

    public record Summary(long totalPackets, long forwarded, long dropped, long errors) {}

    public static JobView of(AnalysisJob job) {
        JobStatus status = job.status();   // read once, so all fields below belong to the same moment
        Summary summary = null;
        if (status == JobStatus.COMPLETED) {
            AnalysisReport r = job.report();
            summary = new Summary(r.totalPackets(), r.forwarded(), r.dropped(), r.errors());
        }
        return new JobView(job.id(), status.name(), job.displayName(), job.createdAt(), job.startedAt(),
                job.finishedAt(), job.error(), job.rules(), summary);
    }
}