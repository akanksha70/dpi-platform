package com.akanksha.dpi.service.job;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
class JpaJobStoreIntegrationTest {

    @Autowired
    private JobStore store;
    @Autowired
    private JobRecordRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    private static ReportData sampleReport() {
        return new ReportData(77, 5738, 73, 4, 0, 77, 0, 0,
                List.of(10L, 20L, 20L, 27L),
                List.of(new ReportData.AppCount("HTTPS", 39)),
                List.of(new ReportData.DomainView("github.com", "GitHub")),
                List.of(new ReportData.FlowView("1.1.1.1", 1234, "2.2.2.2", 443, "TCP",
                        "GitHub", "github.com", 5, 600, 0, false)),
                1, 1, false);
    }

    private static AnalysisJob newJob(String id) {
        return new AnalysisJob(id, id + ".pcap", RuleSpec.empty());
    }

    @Test
    void savesAndReloadsACompletedJobIncludingItsReport() {
        ReportData report = sampleReport();
        AnalysisJob job = new AnalysisJob("job-1", "a.pcap",
                RuleSpec.of(List.of("10.0.0.1"), List.of("YouTube"), List.of("x.com")));

        store.save(job);
        assertEquals(JobStatus.QUEUED, store.find("job-1").orElseThrow().status());

        job.markRunning();
        store.save(job);
        job.markCompleted(report);
        store.save(job);

        AnalysisJob loaded = store.find("job-1").orElseThrow();
        assertEquals(JobStatus.COMPLETED, loaded.status());
        assertEquals("a.pcap", loaded.displayName());
        assertEquals(job.rules(), loaded.rules());
        assertEquals(report, loaded.report());
        assertNotNull(loaded.startedAt());
        assertNotNull(loaded.finishedAt());
    }

    @Test
    void listingDoesNotLoadReports() {
        AnalysisJob job = newJob("job-2");
        job.markCompleted(sampleReport());
        store.save(job);

        List<AnalysisJob> recent = store.recent(10);

        assertEquals(1, recent.size());
        assertEquals(JobStatus.COMPLETED, recent.get(0).status());
        assertNull(recent.get(0).report());
    }

    @Test
    void interruptedJobsAreMarkedFailed() {
        AnalysisJob queued = newJob("queued");
        AnalysisJob running = newJob("running");
        running.markRunning();
        AnalysisJob done = newJob("done");
        done.markCompleted(sampleReport());
        store.save(queued);
        store.save(running);
        store.save(done);

        List<String> failed = store.failInterrupted("restart");

        assertEquals(Set.of("queued", "running"), new HashSet<>(failed));
        for (String id : failed) {
            AnalysisJob job = store.find(id).orElseThrow();
            assertEquals(JobStatus.FAILED, job.status());
            assertEquals("restart", job.error());
        }
        assertEquals(JobStatus.COMPLETED, store.find("done").orElseThrow().status());
    }

    @Test
    void onlyOldFinishedJobsAreDeleted() {
        AnalysisJob done = newJob("done");
        done.markCompleted(sampleReport());
        AnalysisJob running = newJob("running");
        running.markRunning();
        store.save(done);
        store.save(running);

        assertTrue(store.deleteFinishedBefore(Instant.now().minusSeconds(3600)).isEmpty());

        assertEquals(List.of("done"), store.deleteFinishedBefore(Instant.now().plusSeconds(5)));
        assertTrue(store.find("done").isEmpty());
        assertTrue(store.find("running").isPresent());
    }
}