package com.github.runeflobakk.security.voter;


import static org.apache.commons.collections15.CollectionUtils.exists;
import static org.apache.commons.collections15.CollectionUtils.select;
import static org.apache.commons.lang3.StringUtils.isNumeric;
import static org.apache.commons.lang3.StringUtils.removeStart;

import java.util.Collection;

import org.apache.commons.collections15.Predicate;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import com.github.runeflobakk.security.MyPrincipal;


/**
 * Votes if a {@link ConfigAttribute#getAttribute()} starts with a prefix
 * indicating that it is a security level. The default prefix string is
 * <Code>SECURITY_LEVEL_</code>, but this may be overridden to any value.
 * <p/>
 * Abstains from voting if no configuration attribute commences with the
 * security level prefix. Votes to grant access if the user principal is of type
 * {@link no.nav.sbl.security.domain.NavPrincipal} and the security level is
 * equal to or greater than the security level indicated by a
 * <code>ConfigAttribute</code> starting with the security level prefix. Votes
 * to deny access if user principal is not of type
 * {@link no.nav.sbl.security.domain.NavPrincipal} or if the granted security
 * level is less than the required security level indicated by a
 * <code>ConfigAttribute</code> starting with the security level prefix.
 * <p/>
 * All comparisons and prefixes are case sensitive.
 */
public class SecurityLevelVoter implements AccessDecisionVoter {

    private String securityLevelPrefix = "SECURITY_LEVEL_";

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(getSecurityLevelPrefix());
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        Collection<ConfigAttribute> supportedAttributes = select(attributes, new SupportedBy(this));
        if (supportedAttributes.isEmpty()) {
            return ACCESS_ABSTAIN;
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof MyPrincipal && exists(supportedAttributes, acceptingSecurityLevelOf((MyPrincipal) principal))) {
            return ACCESS_GRANTED;
        } else {
            return ACCESS_DENIED;
        }

    }

    private Predicate<ConfigAttribute> acceptingSecurityLevelOf(MyPrincipal navPrincipal) {
        return new AcceptingSecurityLevelOf(navPrincipal);
    }

    private class AcceptingSecurityLevelOf implements Predicate<ConfigAttribute> {

        private final int principalSecurityLevel;

        public AcceptingSecurityLevelOf(MyPrincipal principal) {
            String securityLevelString = principal.getTilgangsniva();
            if (isNumeric(securityLevelString)) {
                principalSecurityLevel = Integer.parseInt(securityLevelString);
            } else {
                principalSecurityLevel = Integer.MIN_VALUE;
            }
        }

        @Override
        public boolean evaluate(ConfigAttribute attribute) {
            int requiredSecurityLevel = getRequiredSecurityLevel(attribute);
            return principalSecurityLevel >= requiredSecurityLevel;
        }

        private int getRequiredSecurityLevel(ConfigAttribute attribute) {
            String requiredSecurityLevelString = removeStart(attribute.getAttribute(), getSecurityLevelPrefix());
            if (isNumeric(requiredSecurityLevelString)) {
                return Integer.parseInt(requiredSecurityLevelString);
            } else {
                return Integer.MAX_VALUE;
            }
        }
    }


    public String getSecurityLevelPrefix() {
        return securityLevelPrefix;
    }

    public void setSecurityLevelPrefix(String securityLevelPrefix) {
        this.securityLevelPrefix = securityLevelPrefix;
    }
}
