package com.akanksha.dpi.service.api;

/** JSON body of POST /api/rules, for example {"type":"APP","value":"YouTube"}. */
public record CreateRuleRequest(String type, String value) {}