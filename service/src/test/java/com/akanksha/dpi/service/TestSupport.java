package com.akanksha.dpi.service;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.service.job.AnalysisJob;
import com.akanksha.dpi.service.job.JobService;
import com.akanksha.dpi.service.job.JobStatus;
import com.akanksha.dpi.service.job.InMemoryJobStore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public final class TestSupport {
    private TestSupport() {}

    public static byte[] samplePcap() throws IOException {
        try (InputStream in = TestSupport.class.getResourceAsStream("/test_dpi.pcap")) {
            if (in == null) throw new IOException("test_dpi.pcap is missing from service/src/test/resources");
            return in.readAllBytes();
        }
    }

       public static JobService newJobService(Path storageDir, ExecutorService executor) throws IOException {
        return new JobService(AppClassifier.loadDefault(), executor, new InMemoryJobStore(), storageDir, 4);
    }

    /** Polls until the job is COMPLETED or FAILED (at most 15 seconds). */
    public static AnalysisJob awaitFinished(JobService jobs, String id) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            AnalysisJob job = jobs.get(id);
            if (job.status() == JobStatus.COMPLETED || job.status() == JobStatus.FAILED) return job;
            Thread.sleep(25);
        }
        throw new AssertionError("Job " + id + " did not finish within 15 seconds");
    }
}