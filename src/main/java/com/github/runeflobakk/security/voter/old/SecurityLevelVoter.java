package com.github.runeflobakk.security.voter.old;

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

                    int securityLevel = getUserSecurityLevel(principal);
                    if (securityLevel >= requiredSecurityLevel) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }
        return result;
    }

    private int getRequiredSecurityLevel(ConfigAttribute attribute) {
        String requiredSecurityLevelString = attribute.getAttribute().replaceFirst(getSecurityLevelPrefix(), "");
        try {
            return Integer.parseInt(requiredSecurityLevelString);
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    private int getUserSecurityLevel(Object principal) {
        String securityLevelString = ((MyPrincipal) principal).getSecurityLevel();
        try {
            return Integer.parseInt(securityLevelString);
        } catch (NumberFormatException e) {
            return Integer.MIN_VALUE;
        }
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(getSecurityLevelPrefix());
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    public String getSecurityLevelPrefix() {
        return securityLevelPrefix;
    }

    public void setSecurityLevelPrefix(String securityLevelPrefix) {
        this.securityLevelPrefix = securityLevelPrefix;
    }
}
