package com.akanksha.dpi.service.rules;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/** Spring writes the implementation; the method names below are turned into SQL queries. */
public interface BlockRuleRepository extends JpaRepository<BlockRule, Long> {

    List<BlockRule> findAllByOrderByIdAsc();

    boolean existsByRuleTypeAndRuleValue(String ruleType, String ruleValue);
}