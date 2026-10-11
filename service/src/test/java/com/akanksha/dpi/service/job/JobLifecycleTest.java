package com.akanksha.dpi.service.job;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.service.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JobLifecycleTest {

    @TempDir
    Path tmp;

    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    private AnalysisJob submitSample(JobService jobs) throws Exception {
        try (InputStream in = new ByteArrayInputStream(TestSupport.samplePcap())) {
            return jobs.submit("test_dpi.pcap", in, RuleSpec.empty());
        }
    }

    @Test
    void expiredJobsAreDeletedTogetherWithTheirFiles() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);
        AnalysisJob done = TestSupport.awaitFinished(jobs, submitSample(jobs).id());
        Path output = jobs.outputFile(done);
        assertTrue(Files.exists(output));

        assertEquals(1, jobs.deleteExpired(Instant.now().plusSeconds(60)));

        assertThrows(JobNotFoundException.class, () -> jobs.get(done.id()));
        assertFalse(Files.exists(output), "the filtered file should be deleted with the job");
    }

    @Test
    void jobsAreKeptUntilTheyAreOldEnough() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);
        AnalysisJob done = TestSupport.awaitFinished(jobs, submitSample(jobs).id());

        assertEquals(0, jobs.deleteExpired(Instant.now().minusSeconds(3600)));

        assertEquals(JobStatus.COMPLETED, jobs.get(done.id()).status());
        assertTrue(Files.exists(jobs.outputFile(done)));
    }

    @Test
    void aRestartMarksUnfinishedJobsAsFailed() throws Exception {
        InMemoryJobStore sharedStore = new InMemoryJobStore();

        // The first "run" of the service: its only worker thread is stuck, so the job stays QUEUED.
        ExecutorService stuck = Executors.newSingleThreadExecutor();
        try {
            CountDownLatch never = new CountDownLatch(1);
            stuck.submit(() -> {
                never.await();
                return null;
            });
            JobService firstRun = new JobService(AppClassifier.loadDefault(), stuck, sharedStore, tmp, 4);
            AnalysisJob job = submitSample(firstRun);
            assertEquals(JobStatus.QUEUED, firstRun.get(job.id()).status());
            assertTrue(Files.exists(firstRun.inputFile(job)));

            // The second run of the service: it starts up and cleans up after the first.
            JobService secondRun = new JobService(AppClassifier.loadDefault(), executor, sharedStore, tmp, 4);
            secondRun.recoverInterruptedJobs();

            AnalysisJob after = secondRun.get(job.id());
            assertEquals(JobStatus.FAILED, after.status());
            assertTrue(after.error().contains("restarted"), after.error());
            assertFalse(Files.exists(secondRun.inputFile(after)), "leftover input should be deleted");
        } finally {
            stuck.shutdownNow();   // the stuck task is interrupted; the queued job never runs
        }
    }
}