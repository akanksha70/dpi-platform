package com.akanksha.dpi.service.job;

/** The caller sent something we cannot accept (becomes HTTP 400). */
public class InvalidInputException extends RuntimeException {
    public InvalidInputException(String message) {
        super(message);
    }
}