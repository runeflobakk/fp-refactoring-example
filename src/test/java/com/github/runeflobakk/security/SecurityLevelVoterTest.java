package com.github.runeflobakk.security;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_ABSTAIN;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_DENIED;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_GRANTED;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import com.github.runeflobakk.security.voter.SecurityLevelVoter;

@RunWith(MockitoJUnitRunner.class)
public class SecurityLevelVoterTest {

    private static final String SECURITY_LEVEL_1 = "SECURITY_LEVEL_1";
    private static final String SECURITY_LEVEL_2 = "SECURITY_LEVEL_2";
    private static final String SECURITY_LEVEL_NOT_A_NUMBER = "SECURITY_LEVEL_NOT_A_NUMBER";
    private static final String NOT_A_VALID_PREFIX_1 = "NOT_A_VALID_PREFIX_1";
    private static final String OTHER_CONFIG_ATTRIBUTE = "OTHER_CONFIG_ATTRIBUTE";

    private SecurityLevelVoter securityLevelVoter = new SecurityLevelVoter();

    @Mock
    private ConfigAttribute attribute;

    @Mock
    private User otherUserPrincipal;


    @Test
    public void supportsAllClasses() {
        assertTrue(securityLevelVoter.supports(Object.class));
    }

    @Test
    public void supportsConfigAttributesBeginningWithSecurityLevel() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_1);
        assertTrue(securityLevelVoter.supports(attribute));
    }

    @Test
    public void supportsConfigAttributesBeginningWithCustomPrefix() {
        securityLevelVoter.setSecurityLevelPrefix("SL_");
        when(attribute.getAttribute()).thenReturn("SL_1");
        assertTrue(securityLevelVoter.supports(attribute));
    }

    @Test
    public void doesNotSupportConfigAttributesNotBeginningWithPrefix() {
        when(attribute.getAttribute()).thenReturn(NOT_A_VALID_PREFIX_1);
        assertFalse(securityLevelVoter.supports(attribute));
    }

    @Test
    public void votesAccessGrantedIfUserPrincipalIsOfTypeNavUserPrincipalAndAccessLevelIsAboveOrEqualToRequiredAccessLevel() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_1);
        Authentication authentication = mockAuthentication(mockMyPrincipal("1"));
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_GRANTED));
    }

    @Test
    public void votesAccessDeniedIfUserPrincipalIsOfTypeNavUserPrincipalAndAccessLevelIsBelowRequiredAccessLevel() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_2);
        Authentication authentication = mockAuthentication(mockMyPrincipal("1"));
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_DENIED));
    }

    @Test
    public void votesAccessDeniedIfUserPrincipalIsNotOfTypeMyPrincipal() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_1);
        Authentication authentication = mockAuthentication(otherUserPrincipal);
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_DENIED));
    }

    @Test
    public void abstainsFromVotingIfNoConfigAttributeBeginningWithSecurityLevelIsPresent() {
        when(attribute.getAttribute()).thenReturn(OTHER_CONFIG_ATTRIBUTE);
        Authentication authentication = mockAuthentication(otherUserPrincipal);
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_ABSTAIN));
    }

    @Test
    public void votesAccessDeniedIfUserAccessLevelIsNotANumber() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_2);
        Authentication authentication = mockAuthentication(mockMyPrincipal("NOT A NUMBER"));
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_DENIED));
    }

    @Test
    public void votesAccessDeniedIfRequiredSecurityLevelIsNotANumber() {
        when(attribute.getAttribute()).thenReturn(SECURITY_LEVEL_NOT_A_NUMBER);
        Authentication authentication = mockAuthentication(mockMyPrincipal("1"));
        assertThat(securityLevelVoter.vote(authentication, null, asList(attribute)), is(ACCESS_DENIED));
    }


    private MyPrincipal mockMyPrincipal(String securityLevel) {
        MyPrincipal myPrincipal = mock(MyPrincipal.class);
        when(myPrincipal.getSecurityLevel()).thenReturn(securityLevel);
        return myPrincipal;
    }

    private Authentication mockAuthentication(User principal) {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(principal);
        return authentication;
    }

}
