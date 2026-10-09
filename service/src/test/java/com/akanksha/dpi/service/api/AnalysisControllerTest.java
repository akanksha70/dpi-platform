package com.akanksha.dpi.service.api;

import com.akanksha.dpi.pcap.PcapReader;
import com.akanksha.dpi.service.TestSupport;
import com.akanksha.dpi.service.job.JobService;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AnalysisControllerTest {

    @TempDir
    Path tmp;

    private ExecutorService executor;
    private JobService jobs;
    private MockMvc mvc;

    @BeforeEach
    void setUp() throws Exception {
        executor = Executors.newFixedThreadPool(2);
        jobs = TestSupport.newJobService(tmp, executor);
        mvc = MockMvcBuilders.standaloneSetup(new AnalysisController(jobs))
                .setControllerAdvice(new ApiExceptionHandler())
                .build();
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    private static MockMultipartFile sample() throws IOException {
        return new MockMultipartFile("file", "test_dpi.pcap", "application/octet-stream", TestSupport.samplePcap());
    }

    /** Uploads the sample (extra arguments are name/value pairs like "blockApp", "YouTube") and waits for it. */
    private String submitAndWait(String... params) throws Exception {
        var request = multipart("/api/analyses").file(sample());
        for (int i = 0; i + 1 < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        MvcResult result = mvc.perform(request).andExpect(status().isAccepted()).andReturn();
        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.id");
        TestSupport.awaitFinished(jobs, id);
        return id;
    }

    @Test
    void uploadIsAcceptedAndReturnsLocation() throws Exception {
        MvcResult result = mvc.perform(multipart("/api/analyses").file(sample()))
                .andExpect(status().isAccepted())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.fileName").value("test_dpi.pcap"))
                .andReturn();

        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.id");
        TestSupport.awaitFinished(jobs, id);

        mvc.perform(get("/api/analyses/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.summary.totalPackets").value(77));
    }

    @Test
    void reportMatchesTheCppBaseline() throws Exception {
        String id = submitAndWait();

        mvc.perform(get("/api/analyses/" + id + "/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalPackets").value(77))
                .andExpect(jsonPath("$.totalBytes").value(5738))
                .andExpect(jsonPath("$.tcpPackets").value(73))
                .andExpect(jsonPath("$.udpPackets").value(4))
                .andExpect(jsonPath("$.forwarded").value(77))
                .andExpect(jsonPath("$.dropped").value(0))
                .andExpect(jsonPath("$.packetsPerWorker", hasSize(4)))
                .andExpect(jsonPath("$.domains", hasSize(18)))
                .andExpect(jsonPath("$.domains[?(@.domain=='www.netflix.com')].app", hasItem("Netflix")))
                .andExpect(jsonPath("$.domains[?(@.domain=='www.microsoft.com')].app", hasItem("Microsoft")));
    }

    @Test
    void blockingTwitterOnlyDropsTwitterFlows() throws Exception {
        String id = submitAndWait("blockApp", "Twitter/X");

        mvc.perform(get("/api/analyses/" + id + "/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dropped", greaterThan(0)))
                .andExpect(jsonPath("$.flows[?(@.sni=='twitter.com')].blocked", hasItem(true)))
                .andExpect(jsonPath("$.flows[?(@.sni=='www.netflix.com')].blocked", hasItem(false)))
                .andExpect(jsonPath("$.flows[?(@.sni=='www.microsoft.com')].blocked", hasItem(false)));
    }

    @Test
    void outputIsAValidPcapWithAllPackets() throws Exception {
        String id = submitAndWait();

        byte[] out = mvc.perform(get("/api/analyses/" + id + "/output"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/vnd.tcpdump.pcap"))
                .andExpect(header().string("Content-Disposition", containsString("filtered-test_dpi.pcap")))
                .andReturn().getResponse().getContentAsByteArray();

        // PCAP magic number as written by our PcapWriter (little-endian): d4 c3 b2 a1
        assertEquals((byte) 0xd4, out[0]);
        assertEquals((byte) 0xc3, out[1]);
        assertEquals((byte) 0xb2, out[2]);
        assertEquals((byte) 0xa1, out[3]);

        int packets = 0;
        try (PcapReader reader = new PcapReader(new ByteArrayInputStream(out))) {
            while (reader.readNext().isPresent()) packets++;
        }
        assertEquals(77, packets);
    }

    @Test
    void rejectsBadInput() throws Exception {
        MockMultipartFile notPcap = new MockMultipartFile("file", "fake.pcap", "application/octet-stream",
                "this is definitely not a packet capture file".getBytes());
        mvc.perform(multipart("/api/analyses").file(notPcap)).andExpect(status().isBadRequest());

        MockMultipartFile empty = new MockMultipartFile("file", "empty.pcap", "application/octet-stream", new byte[0]);
        mvc.perform(multipart("/api/analyses").file(empty)).andExpect(status().isBadRequest());

        var badApp = multipart("/api/analyses").file(sample());
        badApp.param("blockApp", "NotAnApp");
        mvc.perform(badApp).andExpect(status().isBadRequest());

        var badIp = multipart("/api/analyses").file(sample());
        badIp.param("blockIp", "999.1.1.1");
        mvc.perform(badIp).andExpect(status().isBadRequest());
    }

    @Test
    void unknownJobReturns404() throws Exception {
        mvc.perform(get("/api/analyses/does-not-exist")).andExpect(status().isNotFound());
        mvc.perform(get("/api/analyses/does-not-exist/report")).andExpect(status().isNotFound());
        mvc.perform(get("/api/analyses/does-not-exist/output")).andExpect(status().isNotFound());
    }

    @Test
    void listContainsSubmittedJobs() throws Exception {
        String first = submitAndWait();
        String second = submitAndWait();

        mvc.perform(get("/api/analyses"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].id", hasItems(first, second)));
    }

    @Test
    void reportIsNotAvailableUntilTheJobFinishes() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService single = Executors.newSingleThreadExecutor();
        try {
            // This task occupies the only thread, so the real job has to wait in the queue.
            single.submit(() -> {
                release.await();
                return null;
            });
            JobService slowJobs = TestSupport.newJobService(tmp.resolve("slow"), single);
            MockMvc slowMvc = MockMvcBuilders.standaloneSetup(new AnalysisController(slowJobs))
                    .setControllerAdvice(new ApiExceptionHandler())
                    .build();

            MvcResult result = slowMvc.perform(multipart("/api/analyses").file(sample()))
                    .andExpect(status().isAccepted())
                    .andReturn();
            String id = JsonPath.read(result.getResponse().getContentAsString(), "$.id");

            slowMvc.perform(get("/api/analyses/" + id + "/report")).andExpect(status().isConflict());
            slowMvc.perform(get("/api/analyses/" + id + "/output")).andExpect(status().isConflict());

            release.countDown();
            TestSupport.awaitFinished(slowJobs, id);
        } finally {
            release.countDown();
            single.shutdownNow();
        }
    }
}