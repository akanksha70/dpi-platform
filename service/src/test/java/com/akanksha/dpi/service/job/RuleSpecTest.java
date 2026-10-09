package com.akanksha.dpi.service.job;

import com.akanksha.dpi.model.AppType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleSpecTest {

    @Test
    void cleansAndNormalizesInput() {
        RuleSpec spec = RuleSpec.of(
                List.of(" 192.168.001.050 ", ""),
                List.of(" twitter ", "YouTube", "youtube"),
                List.of(" WWW.Example.COM. "));

        assertEquals(List.of("192.168.1.50"), spec.blockIps());
        assertEquals(List.of("Twitter/X", "YouTube"), spec.blockApps());
        assertEquals(List.of("www.example.com"), spec.blockDomains());
    }

    @Test
    void rejectsInvalidIps() {
        for (String bad : new String[]{"999.1.1.1", "1.2.3", "abc", "1.2.3.4.5", "1..2.3"}) {
            assertThrows(InvalidInputException.class, () -> RuleSpec.of(List.of(bad), null, null), bad);
        }
    }

    @Test
    void rejectsUnknownApps() {
        assertThrows(InvalidInputException.class, () -> RuleSpec.of(null, List.of("NotAnApp"), null));
    }

    @Test
    void rejectsInvalidDomains() {
        for (String bad : new String[]{"nodots", "bad domain.com", "-bad.com", "a..b.com", "x.com/path"}) {
            assertThrows(InvalidInputException.class, () -> RuleSpec.of(null, null, List.of(bad)), bad);
        }
    }

    @Test
    void buildsEngineRules() {
        var rules = RuleSpec.of(null, List.of("YouTube"), List.of("x.com")).toRules();
        assertTrue(rules.isBlocked("1.2.3.4", AppType.YOUTUBE, ""));
        assertTrue(rules.isBlocked("1.2.3.4", AppType.TWITTER, "www.x.com"));
    }
}