package com.akanksha.dpi.service.job;

import com.akanksha.dpi.service.TestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JobServiceTest {

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

    private AnalysisJob submitSample(JobService jobs, RuleSpec rules) throws Exception {
        try (InputStream in = new ByteArrayInputStream(TestSupport.samplePcap())) {
            return jobs.submit("test_dpi.pcap", in, rules);
        }
    }

    @Test
    void analysesTheSampleFile() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);
        AnalysisJob job = submitSample(jobs, RuleSpec.empty());
        AnalysisJob done = TestSupport.awaitFinished(jobs, job.id());

        assertEquals(JobStatus.COMPLETED, done.status(), done.error());
        assertEquals(77, done.report().totalPackets());
        assertEquals(77, done.report().forwarded());
        assertTrue(Files.size(jobs.outputFile(done)) > 24);
        assertFalse(Files.exists(jobs.inputFile(done)), "the uploaded input should be deleted after processing");
    }

    @Test
    void blockingTwitterDropsOnlyTwitterTraffic() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);
        AnalysisJob job = submitSample(jobs, RuleSpec.of(null, List.of("Twitter/X"), null));
        AnalysisJob done = TestSupport.awaitFinished(jobs, job.id());

        assertEquals(JobStatus.COMPLETED, done.status(), done.error());
        assertTrue(done.report().dropped() > 0);
        assertTrue(done.report().dropped() < 77);
        for (ReportData.FlowView f : done.report().flows()) {
            if ("www.netflix.com".equals(f.sni()) || "www.microsoft.com".equals(f.sni())) {
                assertEquals(0, f.droppedPackets(), f.sni() + " must not be dropped");
            }
        }
    }

    @Test
    void rejectsFilesThatAreNotPcap() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);

        byte[] notPcap = "this is definitely not a packet capture file".getBytes(StandardCharsets.US_ASCII);
        assertThrows(InvalidInputException.class,
                () -> jobs.submit("fake.pcap", new ByteArrayInputStream(notPcap), RuleSpec.empty()));
        assertThrows(InvalidInputException.class,
                () -> jobs.submit("tiny.pcap", new ByteArrayInputStream(new byte[5]), RuleSpec.empty()));

        assertTrue(jobs.recent(10).isEmpty(), "no job should be created for a rejected upload");
        try (Stream<Path> files = Files.list(tmp)) {
            assertEquals(0, files.count(), "rejected uploads must not leave files behind");
        }
    }

    @Test
    void unknownJobIdThrows() throws Exception {
        JobService jobs = TestSupport.newJobService(tmp, executor);
        assertThrows(JobNotFoundException.class, () -> jobs.get("nope"));
    }

    @Test
    void safeNameStripsPathsAndOddCharacters() {
        assertEquals("passwd", JobService.safeName("../../etc/passwd"));
        assertEquals("my_capture__1_.pcap", JobService.safeName("my capture (1).pcap"));
        assertEquals("capture.pcap", JobService.safeName("  "));
        assertEquals("capture.pcap", JobService.safeName(null));
    }
}