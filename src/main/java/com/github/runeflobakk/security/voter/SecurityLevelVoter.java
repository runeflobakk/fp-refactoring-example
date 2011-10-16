package com.github.runeflobakk.security.voter;

import static org.apache.commons.collections15.CollectionUtils.exists;
import static org.apache.commons.collections15.CollectionUtils.select;
import static org.apache.commons.lang3.StringUtils.removeStart;
import static org.apache.commons.lang3.math.NumberUtils.toInt;

import java.util.Collection;

import org.apache.commons.collections15.Predicate;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import com.github.runeflobakk.security.MyPrincipal;


public class SecurityLevelVoter implements AccessDecisionVoter {

    private String securityLevelPrefix = "SECURITY_LEVEL_";

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        Collection<ConfigAttribute> supportedAttributes = select(attributes, new SupportedBy(this));
        if (supportedAttributes.isEmpty()) {
            return ACCESS_ABSTAIN;
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof MyPrincipal && exists(supportedAttributes, new AcceptingSecurityLevelOf((MyPrincipal) principal))) {
            return ACCESS_GRANTED;
        } else {
            return ACCESS_DENIED;
        }
    }

    private class AcceptingSecurityLevelOf implements Predicate<ConfigAttribute> {

        private final int principalSecurityLevel;

        public AcceptingSecurityLevelOf(MyPrincipal principal) {
            principalSecurityLevel = toInt(principal.getSecurityLevel(), Integer.MIN_VALUE);
        }

        @Override
        public boolean evaluate(ConfigAttribute attribute) {
            String requiredSecurityLevel = removeStart(attribute.getAttribute(), securityLevelPrefix);
            return principalSecurityLevel >= toInt(requiredSecurityLevel, Integer.MAX_VALUE);
        }
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(securityLevelPrefix);
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    public void setSecurityLevelPrefix(String securityLevelPrefix) {
        this.securityLevelPrefix = securityLevelPrefix;
    }
}
