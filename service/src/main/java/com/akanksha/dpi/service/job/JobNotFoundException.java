package com.akanksha.dpi.service.job;

/** No job with that id (becomes HTTP 404). */
public class JobNotFoundException extends RuntimeException {
    public JobNotFoundException(String id) {
        super("No analysis job with id '" + (id.length() > 60 ? id.substring(0, 60) + "..." : id) + "'");
    }
}