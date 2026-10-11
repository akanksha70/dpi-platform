package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.job.InvalidInputException;
import com.akanksha.dpi.service.job.JobNotFoundException;
import com.akanksha.dpi.service.job.JobNotReadyException;
import com.akanksha.dpi.service.job.OutputGoneException;
import com.akanksha.dpi.service.rules.DuplicateRuleException;
import com.akanksha.dpi.service.rules.RuleNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Turns exceptions into error responses (RFC 9457 "problem details").
 * Extending ResponseEntityExceptionHandler keeps Spring's own correct statuses for things like
 * a missing upload part (400) or a wrong HTTP method (405), so the catch-all below
 * only sees genuinely unexpected errors.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(InvalidInputException.class)
    ResponseEntity<ProblemDetail> invalidInput(InvalidInputException e) {
        return respond(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler({JobNotFoundException.class, RuleNotFoundException.class})
    ResponseEntity<ProblemDetail> notFound(RuntimeException e) {
        return respond(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler({JobNotReadyException.class, DuplicateRuleException.class})
    ResponseEntity<ProblemDetail> conflict(RuntimeException e) {
        return respond(HttpStatus.CONFLICT, e.getMessage());
    }

        @ExceptionHandler(OutputGoneException.class)
    ResponseEntity<ProblemDetail> gone(OutputGoneException e) {
        return respond(HttpStatus.GONE, e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> unexpected(Exception e) {
        log.error("Unexpected error", e);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected server error");
    }

    private static ResponseEntity<ProblemDetail> respond(HttpStatus status, String detail) {
        return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(status, detail));
    }
}