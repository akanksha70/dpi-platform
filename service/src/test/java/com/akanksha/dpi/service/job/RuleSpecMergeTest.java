package com.akanksha.dpi.service.job;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuleSpecMergeTest {

    @Test
    void mergeKeepsOrderAndDropsDuplicates() {
        RuleSpec stored = RuleSpec.of(List.of("10.0.0.1"), List.of("YouTube"), List.of("x.com"));
        RuleSpec requested = RuleSpec.of(List.of("10.0.0.1", "10.0.0.2"), List.of("Twitter/X", "YouTube"), null);

        RuleSpec merged = stored.merge(requested);

        assertEquals(List.of("10.0.0.1", "10.0.0.2"), merged.blockIps());
        assertEquals(List.of("YouTube", "Twitter/X"), merged.blockApps());
        assertEquals(List.of("x.com"), merged.blockDomains());
    }
}