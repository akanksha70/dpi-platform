package com.akanksha.dpi.service.job;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Stores jobs in the database. Rules and reports are kept as JSON text. */
@Component
public class JpaJobStore implements JobStore {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final JobRecordRepository repository;

    public JpaJobStore(JobRecordRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional
    public void save(AnalysisJob job) {
        String reportJson = job.report() == null ? null : toJson(job.report());
        repository.save(JobRecord.from(job, toJson(job.rules()), reportJson));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<AnalysisJob> find(String id) {
        return repository.findById(id).map(r -> toJob(r, true));
    }

    @Override
    @Transactional(readOnly = true)
    public List<AnalysisJob> recent(int limit) {
        PageRequest page = PageRequest.of(0, limit, Sort.by(Sort.Direction.DESC, "createdAt"));
        return repository.findAll(page).getContent().stream().map(r -> toJob(r, false)).toList();
    }

    @Override
    @Transactional
    public List<String> failInterrupted(String reason) {
        List<JobRecord> stuck = repository.findByStatusIn(
                List.of(JobStatus.QUEUED.name(), JobStatus.RUNNING.name()));
        Instant now = Instant.now();
        for (JobRecord r : stuck) {
            r.markFailed(reason, now);   // saved automatically when the transaction ends
        }
        return stuck.stream().map(JobRecord::getId).toList();
    }

    @Override
    @Transactional
    public List<String> deleteFinishedBefore(Instant cutoff) {
        List<JobRecord> old = repository.findByFinishedAtBefore(cutoff);
        List<String> ids = old.stream().map(JobRecord::getId).toList();
        repository.deleteAll(old);
        return ids;
    }

    private AnalysisJob toJob(JobRecord r, boolean withReport) {
        RuleSpec rules = fromJson(r.getRulesJson(), RuleSpec.class);
        ReportData report = (withReport && r.getReportJson() != null)
                ? fromJson(r.getReportJson(), ReportData.class)
                : null;
        return AnalysisJob.restore(r.getId(), r.getFileName(), rules, r.getCreatedAt(),
                JobStatus.valueOf(r.getStatus()), r.getStartedAt(), r.getFinishedAt(), r.getError(), report);
    }

    private static String toJson(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not convert " + value.getClass().getSimpleName() + " to JSON", e);
        }
    }

    private static <T> T fromJson(String json, Class<T> type) {
        try {
            return JSON.readValue(json, type);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not read stored " + type.getSimpleName(), e);
        }
    }
}