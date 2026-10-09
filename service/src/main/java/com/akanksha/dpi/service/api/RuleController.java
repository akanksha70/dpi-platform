package com.akanksha.dpi.service.api;

import com.akanksha.dpi.service.job.InvalidInputException;
import com.akanksha.dpi.service.rules.BlockRule;
import com.akanksha.dpi.service.rules.RuleService;
import com.akanksha.dpi.service.rules.RuleType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final RuleService rules;

    public RuleController(RuleService rules) {
        this.rules = rules;
    }

    @GetMapping
    public List<RuleView> list() {
        return rules.list().stream().map(RuleView::of).toList();
    }

    @PostMapping
    public ResponseEntity<RuleView> create(@RequestBody CreateRuleRequest request) {
        if (request.type() == null) {
            throw new InvalidInputException("type is required (IP, APP or DOMAIN)");
        }
        BlockRule rule = rules.add(RuleType.parse(request.type()), request.value());
        return ResponseEntity.created(URI.create("/api/rules/" + rule.getId())).body(RuleView.of(rule));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") long id) {
        rules.delete(id);
        return ResponseEntity.noContent().build();
    }
}