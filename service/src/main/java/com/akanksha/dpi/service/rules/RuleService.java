package com.akanksha.dpi.service.rules;

import com.akanksha.dpi.service.job.InvalidInputException;
import com.akanksha.dpi.service.job.RuleSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class RuleService {
    private static final Logger log = LoggerFactory.getLogger(RuleService.class);

    private final BlockRuleRepository repository;

    public RuleService(BlockRuleRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<BlockRule> list() {
        return repository.findAllByOrderByIdAsc();
    }

    /** Validates and normalizes the value with the same rules as upload-time rules, then stores it. */
    @Transactional
    public BlockRule add(RuleType type, String rawValue) {
        String value = normalize(type, rawValue);

        boolean exists = repository.existsByRuleTypeAndRuleValue(type.name(), value);
        log.info("Adding rule {} '{}': already stored={}, rows in table={}",
                type, value, exists, repository.count());
        if (exists) {
            throw new DuplicateRuleException(type, value);
        }

        try {
            return repository.saveAndFlush(new BlockRule(type.name(), value));
        } catch (DataIntegrityViolationException e) {
            String cause = String.valueOf(e.getMostSpecificCause().getMessage());
            log.warn("Insert of rule {} '{}' failed: {}", type, value, cause);
            String lower = cause.toLowerCase(Locale.ROOT);
            if (lower.contains("unique") || lower.contains("duplicate")) {
                // Two requests added the same rule at the same moment; the unique constraint caught it.
                throw new DuplicateRuleException(type, value);
            }
            throw e;   // any other database problem is a real error and must not be called "duplicate"
        }
    }

    @Transactional
    public void delete(long id) {
        if (!repository.existsById(id)) throw new RuleNotFoundException(id);
        repository.deleteById(id);
    }

    /** All stored rules as one RuleSpec, ready to be merged into an analysis. */
    @Transactional(readOnly = true)
    public RuleSpec currentSpec() {
        List<String> ips = new ArrayList<>();
        List<String> apps = new ArrayList<>();
        List<String> domains = new ArrayList<>();
        for (BlockRule r : repository.findAllByOrderByIdAsc()) {
            switch (r.getRuleType()) {
                case "IP" -> ips.add(r.getRuleValue());
                case "APP" -> apps.add(r.getRuleValue());
                case "DOMAIN" -> domains.add(r.getRuleValue());
                default -> { }
            }
        }
        return new RuleSpec(ips, apps, domains);
    }

    private static String normalize(RuleType type, String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidInputException("value must not be blank");
        }
        return switch (type) {
            case IP -> RuleSpec.of(List.of(raw), null, null).blockIps().get(0);
            case APP -> RuleSpec.of(null, List.of(raw), null).blockApps().get(0);
            case DOMAIN -> RuleSpec.of(null, null, List.of(raw)).blockDomains().get(0);
        };
    }
}