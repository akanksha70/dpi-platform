package com.akanksha.dpi.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class ServiceApplicationTests {

    @Test
    void contextLoads() {
        // Passes if Spring can build every bean and Flyway can migrate the in-memory database.
    }
}