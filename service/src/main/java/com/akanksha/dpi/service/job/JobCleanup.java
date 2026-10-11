package com.akanksha.dpi.service.job;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/** Deletes old jobs and their files on a schedule. */
@Component
public class JobCleanup {
    private static final Logger log = LoggerFactory.getLogger(JobCleanup.class);

    private final JobService jobs;
    private final long retentionHours;

    public JobCleanup(JobService jobs, @Value("${dpi.retention-hours:24}") long retentionHours) {
        this.jobs = jobs;
        this.retentionHours = retentionHours;
    }

    @Scheduled(initialDelay = 1, fixedDelay = 15, timeUnit = TimeUnit.MINUTES)
    public void cleanUp() {
        try {
            int removed = jobs.deleteExpired(Instant.now().minus(Duration.ofHours(retentionHours)));
            if (removed > 0) log.info("Removed {} expired job(s)", removed);
        } catch (RuntimeException e) {
            log.error("Cleaning up expired jobs failed", e);
        }
    }
}