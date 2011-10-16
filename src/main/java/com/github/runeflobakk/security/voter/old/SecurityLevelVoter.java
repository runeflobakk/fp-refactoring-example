package com.github.runeflobakk.security.voter.old;

import static org.apache.commons.lang3.StringUtils.removeStart;
import static org.apache.commons.lang3.math.NumberUtils.toInt;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import com.github.runeflobakk.security.MyPrincipal;


public class SecurityLevelVoter implements AccessDecisionVoter {

    private String securityLevelPrefix = "SECURITY_LEVEL_";

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        int result = ACCESS_ABSTAIN;
        Object principal = authentication.getPrincipal();
        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                if (principal instanceof MyPrincipal) {
                    int requiredSecurityLevel = getRequiredSecurityLevel(attribute);

                    int securityLevel = getUserSecurityLevel((MyPrincipal) principal);
                    if (securityLevel >= requiredSecurityLevel) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }
        return result;
    }

    private int getRequiredSecurityLevel(ConfigAttribute attribute) {
        String requiredSecurityLevel = removeStart(attribute.getAttribute(), securityLevelPrefix);
        return toInt(requiredSecurityLevel, Integer.MAX_VALUE);
    }

    private int getUserSecurityLevel(MyPrincipal principal) {
        return toInt(principal.getSecurityLevel(), Integer.MIN_VALUE);
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
