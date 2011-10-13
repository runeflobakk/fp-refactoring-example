package com.github.runeflobakk.security;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import com.github.runeflobakk.security.MyPrincipal;
import com.github.runeflobakk.security.voter.SecurityLevelVoter;

/**
 * Tests for {@link no.nav.sbl.security.voters.SecurityLevelVoter}
 */
public class SecurityLevelVoterTest {
   private SecurityLevelVoter securityLevelVoter;
   private static final String SECURITY_LEVEL_1 = "SECURITY_LEVEL_1";
   private static final String SECURITY_LEVEL_2 = "SECURITY_LEVEL_2";
   private static final String SECURITY_LEVEL_NOT_A_NUMBER = "SECURITY_LEVEL_NOT_A_NUMBER";
   private static final String NOT_A_VALID_PREFIX_1 = "NOT_A_VALID_PREFIX_1";
   private static final String OTHER_CONFIG_ATTRIBUTE = "OTHER_CONFIG_ATTRIBUTE";


   @Before
   public void setUp() throws Exception {
      securityLevelVoter = new SecurityLevelVoter();
   }

   @Test
   public void supportsAllClasses() {
      boolean result = securityLevelVoter.supports(Object.class);
      assertTrue(result);
   }

   @Test
   public void supportsConfigAttributesBeginningWithSecurityLevel() {
      ConfigAttribute configAttribute = mockConfigAttribute(SECURITY_LEVEL_1);
      boolean result = securityLevelVoter.supports(configAttribute);

      assertTrue(result);
   }

   @Test
   public void supportsConfigAttributesBeginningWithCustomPrefix() {
      ConfigAttribute configAttribute = mockConfigAttribute("SL_1");

      securityLevelVoter.setSecurityLevelPrefix("SL_");
      boolean result = securityLevelVoter.supports(configAttribute);

      assertTrue(result);
   }

   @Test
   public void doesNotSupportConfigAttributesNotBeginningWithPrefix() {
      ConfigAttribute configAttribute = mockConfigAttribute(NOT_A_VALID_PREFIX_1);
      boolean result = securityLevelVoter.supports(configAttribute);

      assertFalse(result);
   }

   @Test
   public void votesAccessGrantedIfUserPrincipalIsOfTypeNavUserPrincipalAndAccessLevelIsAboveOrEqualToRequiredAccessLevel() {
      ConfigAttribute attribute = mockConfigAttribute(SECURITY_LEVEL_1);
      Authentication authentication = mockAuthentication(mockMyPrincipal("1"));

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_GRANTED, result);
   }

   @Test
   public void votesAccessDeniedIfUserPrincipalIsOfTypeNavUserPrincipalAndAccessLevelIsBelowRequiredAccessLevel() {
      ConfigAttribute attribute = mockConfigAttribute(SECURITY_LEVEL_2);
      Authentication authentication = mockAuthentication(mockMyPrincipal("1"));

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_DENIED, result);
   }

   @Test
   public void votesAccessDeniedIfUserPrincipalIsNotOfTypeMyPrincipal() {
      ConfigAttribute attribute = mockConfigAttribute(SECURITY_LEVEL_1);
      Authentication authentication = mockAuthentication(mockOtherUserPrincipal());

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_DENIED, result);
   }

   @Test
   public void votesAccessAbstainIfNoConfigAttributeBeginningWithSecurityLevelIsPresent() {
      ConfigAttribute attribute = mockConfigAttribute(OTHER_CONFIG_ATTRIBUTE);
      Authentication authentication = mockAuthentication(mockOtherUserPrincipal());

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_ABSTAIN, result);
   }

   @Test
   public void votesAccessDeniedIfUserAccessLevelIsNotANumber() {
      ConfigAttribute attribute = mockConfigAttribute(SECURITY_LEVEL_2);
      Authentication authentication = mockAuthentication(mockMyPrincipal("NOT A NUMBER"));

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_DENIED, result);
   }

   @Test
   public void votesAccessDeniedIfRequiredSecurityLevelIsNotANumber() {
      ConfigAttribute attribute = mockConfigAttribute(SECURITY_LEVEL_NOT_A_NUMBER);
      Authentication authentication = mockAuthentication(mockMyPrincipal("1"));

      int result = securityLevelVoter.vote(authentication, null, asList(attribute));

      assertEquals(AccessDecisionVoter.ACCESS_DENIED, result);
   }

   private MyPrincipal mockMyPrincipal(String securityLevel) {
      MyPrincipal MyPrincipal = mock(MyPrincipal.class);
      when(MyPrincipal.getTilgangsniva()).thenReturn(securityLevel);
      return MyPrincipal;
   }

   private Authentication mockAuthentication(User MyPrincipal) {
      Authentication authentication = mock(Authentication.class);
      when(authentication.getPrincipal()).thenReturn(MyPrincipal);
      return authentication;
   }

   private ConfigAttribute mockConfigAttribute(String attribute) {
      ConfigAttribute configAttribute = mock(ConfigAttribute.class);
      when(configAttribute.getAttribute()).thenReturn(attribute);
      return configAttribute;
   }

   private User mockOtherUserPrincipal() {
      User principal = mock(User.class);
      return principal;
   }

}
