package com.akanksha.dpi.engine;

import com.akanksha.dpi.model.AppType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RulesTest {

    @Test
    void blockingTwitterNoLongerBlocksNetflix() {
        Rules r = new Rules();
        r.blockApp("Twitter/X");
        assertTrue(r.isBlocked("10.0.0.1", AppType.TWITTER, "twitter.com"));
        assertFalse(r.isBlocked("10.0.0.1", AppType.NETFLIX, "www.netflix.com"));
    }

    @Test
    void domainRulesMatchWholeDomainsOnly() {
        Rules r = new Rules();
        r.blockDomain("x.com");
        assertTrue(r.isBlocked("10.0.0.1", AppType.TWITTER, "www.x.com"));
        assertFalse(r.isBlocked("10.0.0.1", AppType.NETFLIX, "www.netflix.com"));
    }

    @Test
    void blocksByIp() {
        Rules r = new Rules();
        r.blockIp("192.168.1.50");
        assertTrue(r.isBlocked("192.168.1.50", AppType.UNKNOWN, null));
        assertFalse(r.isBlocked("192.168.1.51", AppType.UNKNOWN, null));
    }

    @Test
    void rejectsUnknownAppNames() {
        assertThrows(IllegalArgumentException.class, () -> new Rules().blockApp("NotAnApp"));
    }
}