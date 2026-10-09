package com.akanksha.dpi.service.rules;

import com.akanksha.dpi.service.job.InvalidInputException;

public enum RuleType {
    IP, APP, DOMAIN;

    public static RuleType parse(String text) {
        if (text != null) {
            for (RuleType t : values()) {
                if (t.name().equalsIgnoreCase(text.trim())) return t;
            }
        }
        throw new InvalidInputException("Unknown rule type (use IP, APP or DOMAIN)");
    }
}