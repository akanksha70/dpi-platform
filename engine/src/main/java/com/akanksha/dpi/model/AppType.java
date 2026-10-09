package com.akanksha.dpi.model;

import java.util.Optional;

public enum AppType {
    UNKNOWN("Unknown"), HTTP("HTTP"), HTTPS("HTTPS"), DNS("DNS"), TLS("TLS"), QUIC("QUIC"),
    GOOGLE("Google"), FACEBOOK("Facebook"), YOUTUBE("YouTube"), TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"), NETFLIX("Netflix"), AMAZON("Amazon"), MICROSOFT("Microsoft"),
    APPLE("Apple"), WHATSAPP("WhatsApp"), TELEGRAM("Telegram"), TIKTOK("TikTok"),
    SPOTIFY("Spotify"), ZOOM("Zoom"), DISCORD("Discord"), GITHUB("GitHub"), CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    /** Accepts either the display name ("Twitter/X") or the enum name ("TWITTER"), any capitalization. */
    public static Optional<AppType> fromString(String s) {
        if (s == null) return Optional.empty();
        String t = s.trim();
        for (AppType a : values()) {
            if (a.displayName.equalsIgnoreCase(t) || a.name().equalsIgnoreCase(t)) return Optional.of(a);
        }
        return Optional.empty();
    }
}