package com.akanksha.dpi.service.job;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Keeps jobs in memory. Used by unit tests; the real service uses JpaJobStore. */
public class InMemoryJobStore implements JobStore {
    private final Map<String, AnalysisJob> jobs = new ConcurrentHashMap<>();

    @Override
    public void save(AnalysisJob job) {
        jobs.put(job.id(), job);
    }

    @Override
    public Optional<AnalysisJob> find(String id) {
        return Optional.ofNullable(jobs.get(id));
    }

    @Override
    public List<AnalysisJob> recent(int limit) {
        return jobs.values().stream()
                .sorted(Comparator.comparing(AnalysisJob::createdAt).reversed())
                .limit(limit)
                .toList();
    }

    @Override
    public List<String> failInterrupted(String reason) {
        List<String> ids = new ArrayList<>();
        for (AnalysisJob job : jobs.values()) {
            JobStatus status = job.status();
            if (status == JobStatus.QUEUED || status == JobStatus.RUNNING) {
                job.markFailed(reason);
                ids.add(job.id());
            }
        }
        return ids;
    }

    @Override
    public List<String> deleteFinishedBefore(Instant cutoff) {
        List<String> ids = new ArrayList<>();
        for (AnalysisJob job : jobs.values()) {
            Instant finished = job.finishedAt();
            if (finished != null && finished.isBefore(cutoff)) ids.add(job.id());
        }
        ids.forEach(jobs::remove);
        return ids;
    }
}