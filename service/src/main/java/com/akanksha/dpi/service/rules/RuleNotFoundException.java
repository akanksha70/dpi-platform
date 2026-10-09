package com.akanksha.dpi.service.rules;

/** No rule with that id (becomes HTTP 404). */
public class RuleNotFoundException extends RuntimeException {
    public RuleNotFoundException(long id) {
        super("No rule with id " + id);
    }
}