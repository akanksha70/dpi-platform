package com.akanksha.dpi.service.job;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Where jobs are kept. The service uses a database; tests can use an in-memory version. */
public interface JobStore {

    /** Inserts the job, or updates it if it already exists. */
    void save(AnalysisJob job);

    Optional<AnalysisJob> find(String id);

    /** Newest first. Reports are NOT loaded, to keep listing cheap. */
    List<AnalysisJob> recent(int limit);

    /** Marks jobs left QUEUED or RUNNING by a previous run as FAILED. Returns their ids. */
    List<String> failInterrupted(String reason);

    /** Deletes jobs that finished before the cutoff. Returns their ids so files can be removed too. */
    List<String> deleteFinishedBefore(Instant cutoff);
}