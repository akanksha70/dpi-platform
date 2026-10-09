package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.rules.BlockRule;

import java.time.Instant;

public record RuleView(long id, String type, String value, Instant createdAt) {

    public static RuleView of(BlockRule rule) {
        return new RuleView(rule.getId(), rule.getRuleType(), rule.getRuleValue(), rule.getCreatedAt());
    }
}