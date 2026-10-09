package com.akanksha.dpi.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class FiveTupleTest {

    @Test
    void bothDirectionsShareOneCanonicalKey() {
        FiveTuple clientToServer = new FiveTuple("192.168.1.100", "142.250.185.206", 54321, 443, 6);
        assertEquals(clientToServer.canonical(), clientToServer.reverse().canonical());
    }

    @Test
    void differentConnectionsStayDifferent() {
        FiveTuple a = new FiveTuple("192.168.1.100", "142.250.185.206", 54321, 443, 6);
        FiveTuple b = new FiveTuple("192.168.1.100", "142.250.185.206", 54322, 443, 6);
        assertNotEquals(a.canonical(), b.canonical());
    }
}