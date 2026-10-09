package com.akanksha.dpi.service.job;

/** The job exists but has no result to give yet, or it failed (becomes HTTP 409). */
public class JobNotReadyException extends RuntimeException {
    public JobNotReadyException(String message) {
        super(message);
    }
}