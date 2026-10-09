package com.akanksha.dpi.engine;

import com.akanksha.dpi.classify.DomainMatcher;
import com.akanksha.dpi.model.AppType;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** Blocking rules. Safe to read from many threads while rules are being added. */
public class Rules {
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(ip.trim());
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
    }

    public void blockApp(String name) {
        blockedApps.add(AppType.fromString(name)
                .orElseThrow(() -> new IllegalArgumentException("Unknown app: " + name)));
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.trim());
    }

    /** Domain rules match whole domains only ("x.com" blocks www.x.com but not netflix.com). */
    public boolean isBlocked(String srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(app)) return true;
        if (sni != null && !sni.isEmpty()) {
            for (String d : blockedDomains) {
                if (DomainMatcher.matches(sni, d)) return true;
            }
        }
        return false;
    }
}