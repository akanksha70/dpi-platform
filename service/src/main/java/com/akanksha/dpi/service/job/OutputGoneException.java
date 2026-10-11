package com.akanksha.dpi.service.job;

/** The job exists but its filtered file is gone (becomes HTTP 410). */
public class OutputGoneException extends RuntimeException {
    public OutputGoneException() {
        super("The filtered file is no longer available (it may have been cleaned up)");
    }
}