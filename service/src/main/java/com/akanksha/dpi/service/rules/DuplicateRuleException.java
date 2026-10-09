package com.akanksha.dpi.service.rules;

/** The same rule already exists (becomes HTTP 409). */
public class DuplicateRuleException extends RuntimeException {
    public DuplicateRuleException(RuleType type, String value) {
        super("Rule already exists: " + type + " " + value);
    }
}