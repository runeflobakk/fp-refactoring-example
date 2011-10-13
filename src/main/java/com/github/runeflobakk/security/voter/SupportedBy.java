package com.github.runeflobakk.security.voter;

import org.apache.commons.collections15.Predicate;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;


public class SupportedBy implements Predicate<ConfigAttribute> {

    private final AccessDecisionVoter voter;

    public SupportedBy(AccessDecisionVoter voter) {
        this.voter = voter;
    }

    @Override
    public boolean evaluate(ConfigAttribute attribute) {
        return voter.supports(attribute);
    }
}
