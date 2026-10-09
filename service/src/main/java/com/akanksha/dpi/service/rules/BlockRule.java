
package com.akanksha.dpi.service.rules;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/** One row of the block_rule table. The type is kept as plain text (IP, APP or DOMAIN). */
@Entity
@Table(name = "block_rule")
public class BlockRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)   // the database assigns the id
    private Long id;

    @Column(name = "rule_type", nullable = false, length = 10)
    private String ruleType;

    @Column(name = "rule_value", nullable = false)
    private String ruleValue;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected BlockRule() {
        // required by JPA
    }

    public BlockRule(String ruleType, String ruleValue) {
        this.ruleType = ruleType;
        this.ruleValue = ruleValue;
        this.createdAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }

    public Long getId() { return id; }
    public String getRuleType() { return ruleType; }
    public String getRuleValue() { return ruleValue; }
    public Instant getCreatedAt() { return createdAt; }
}