package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.job.AnalysisJob;
import com.akanksha.dpi.service.job.InvalidInputException;
import com.akanksha.dpi.service.job.JobNotReadyException;
import com.akanksha.dpi.service.job.JobService;
import com.akanksha.dpi.service.job.JobStatus;
import com.akanksha.dpi.service.job.RuleSpec;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/analyses")
public class AnalysisController {

    private final JobService jobs;

    public AnalysisController(JobService jobs) {
        this.jobs = jobs;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<JobView> submit(
            @RequestParam("file") MultipartFile file,
            @RequestParam(name = "blockApp", required = false) List<String> blockApps,
            @RequestParam(name = "blockIp", required = false) List<String> blockIps,
            @RequestParam(name = "blockDomain", required = false) List<String> blockDomains) throws IOException {

        if (file.isEmpty()) {
            throw new InvalidInputException("No file uploaded, or the file is empty");
        }
        RuleSpec rules = RuleSpec.of(blockIps, blockApps, blockDomains);

        AnalysisJob job;
        try (InputStream in = file.getInputStream()) {
            job = jobs.submit(file.getOriginalFilename(), in, rules);
        }
        return ResponseEntity.accepted()
                .location(URI.create("/api/analyses/" + job.id()))
                .body(JobView.of(job));
    }

    @GetMapping
    public List<JobView> list(@RequestParam(name = "limit", defaultValue = "20") int limit) {
        int n = Math.max(1, Math.min(limit, 100));
        return jobs.recent(n).stream().map(JobView::of).toList();
    }

    @GetMapping("/{id}")
    public JobView status(@PathVariable("id") String id) {
        return JobView.of(jobs.get(id));
    }

    @GetMapping("/{id}/report")
    public ReportView report(@PathVariable("id") String id) {
        AnalysisJob job = jobs.get(id);
        requireCompleted(job);
        return ReportView.of(job.id(), job.report());
    }

    @GetMapping("/{id}/output")
    public ResponseEntity<Resource> output(@PathVariable("id") String id) {
        AnalysisJob job = jobs.get(id);
        requireCompleted(job);
        ContentDisposition disposition = ContentDisposition.attachment()
                .filename("filtered-" + job.displayName())
                .build();
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/vnd.tcpdump.pcap"))
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .body(new FileSystemResource(job.outputPath()));
    }

    private static void requireCompleted(AnalysisJob job) {
        JobStatus status = job.status();
        if (status == JobStatus.FAILED) {
            throw new JobNotReadyException("The analysis failed: " + job.error());
        }
        if (status != JobStatus.COMPLETED) {
            throw new JobNotReadyException("The analysis is not finished yet (status: " + status + ")");
        }
    }
}