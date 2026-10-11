package com.akanksha.dpi.service.job;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface JobRecordRepository extends JpaRepository<JobRecord, String> {

    List<JobRecord> findByStatusIn(Collection<String> statuses);

    /** Jobs with no finish time (still running) are never returned. */
    List<JobRecord> findByFinishedAtBefore(Instant cutoff);
}