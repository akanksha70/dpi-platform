package com.akanksha.dpi.classify;

import com.akanksha.dpi.model.AppType;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AppClassifierTest {

    @Test
    void classifiesTheBaselineDomains() throws Exception {
        AppClassifier c = AppClassifier.loadDefault();
        Map<String, AppType> expected = Map.ofEntries(
                Map.entry("httpbin.org", AppType.HTTPS),
                Map.entry("example.com", AppType.HTTPS),
                Map.entry("www.youtube.com", AppType.YOUTUBE),
                Map.entry("www.facebook.com", AppType.FACEBOOK),
                Map.entry("www.microsoft.com", AppType.MICROSOFT),   // C++ said Twitter/X
                Map.entry("github.com", AppType.GITHUB),
                Map.entry("www.instagram.com", AppType.INSTAGRAM),
                Map.entry("discord.com", AppType.DISCORD),
                Map.entry("web.telegram.org", AppType.TELEGRAM),
                Map.entry("www.apple.com", AppType.APPLE),
                Map.entry("twitter.com", AppType.TWITTER),
                Map.entry("open.spotify.com", AppType.SPOTIFY),
                Map.entry("www.google.com", AppType.GOOGLE),
                Map.entry("www.amazon.com", AppType.AMAZON),
                Map.entry("zoom.us", AppType.ZOOM),
                Map.entry("www.cloudflare.com", AppType.CLOUDFLARE),
                Map.entry("www.netflix.com", AppType.NETFLIX),       // C++ said Twitter/X
                Map.entry("www.tiktok.com", AppType.TIKTOK));

        expected.forEach((domain, app) -> assertEquals(app, c.classify(domain), domain));
    }

    @Test
    void fixesOtherSubstringBugs() throws Exception {
        AppClassifier c = AppClassifier.loadDefault();
        assertEquals(AppType.YOUTUBE, c.classify("rr1.googlevideo.com"));  // video CDN belongs to YouTube
        assertEquals(AppType.HTTPS, c.classify("laws.com"));               // C++ matched "aws" inside "laws"
    }

    @Test
    void handlesMissingHost() throws Exception {
        AppClassifier c = AppClassifier.loadDefault();
        assertEquals(AppType.UNKNOWN, c.classify(null));
        assertEquals(AppType.UNKNOWN, c.classify(""));
    }
}