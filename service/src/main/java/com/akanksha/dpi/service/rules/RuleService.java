package com.akanksha.dpi.service.rules;

import com.akanksha.dpi.service.job.InvalidInputException;
import com.akanksha.dpi.service.job.RuleSpec;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class RuleService {

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
        if (repository.existsByRuleTypeAndRuleValue(type.name(), value)) {
            throw new DuplicateRuleException(type, value);
        }
        try {
            return repository.saveAndFlush(new BlockRule(type.name(), value));
        } catch (DataIntegrityViolationException e) {
            // Two requests added the same rule at the same moment; the unique constraint caught it.
            throw new DuplicateRuleException(type, value);
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