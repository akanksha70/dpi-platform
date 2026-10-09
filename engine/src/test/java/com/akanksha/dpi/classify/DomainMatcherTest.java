package com.akanksha.dpi.classify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainMatcherTest {

    @Test
    void matchesExactAndSubdomains() {
        assertTrue(DomainMatcher.matches("x.com", "x.com"));
        assertTrue(DomainMatcher.matches("www.x.com", "x.com"));
        assertTrue(DomainMatcher.matches("WWW.X.COM.", "x.com"));
    }

    @Test
    void rejectsLookalikesThatBrokeTheCppVersion() {
        assertFalse(DomainMatcher.matches("www.netflix.com", "x.com"));
        assertFalse(DomainMatcher.matches("www.microsoft.com", "t.co"));
        assertFalse(DomainMatcher.matches("notx.com", "x.com"));
        assertFalse(DomainMatcher.matches("laws.com", "aws.com"));
    }
}