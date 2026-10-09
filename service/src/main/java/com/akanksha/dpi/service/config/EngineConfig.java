package com.akanksha.dpi.service.config;

import com.akanksha.dpi.classify.AppClassifier;
import com.akanksha.dpi.service.job.JobService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class EngineConfig {

    @Bean
    AppClassifier appClassifier() throws IOException {
        return AppClassifier.loadDefault();
    }

    @Bean(destroyMethod = "shutdown")
    ExecutorService jobExecutor(@Value("${dpi.job-threads:2}") int threads) {
        return Executors.newFixedThreadPool(threads, runnable -> {
            Thread t = new Thread(runnable, "dpi-job");
            t.setDaemon(true);
            return t;
        });
    }

    @Bean
    JobService jobService(AppClassifier classifier,
                          ExecutorService jobExecutor,
                          @Value("${dpi.storage-dir}") String storageDir,
                          @Value("${dpi.workers:4}") int workers) throws IOException {
        return new JobService(classifier, jobExecutor, Path.of(storageDir), workers);
    }
}