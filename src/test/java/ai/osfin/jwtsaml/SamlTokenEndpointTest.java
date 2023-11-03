package ai.osfin.jwtsaml;

import ai.osfin.jwtsaml.controller.MyController;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import ai.osfin.jwtsaml.util.JwtUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SamlTokenEndpointTest {

	@InjectMocks
	private MyController myController;

	@Mock
	private MyUserDetailsService myUserDetailsService;

	@Mock
	private JwtUtil jwtTokenUtil;

	@Mock
	private AuthenticationManager authenticationManager;

	// Mock principal
	@Mock
	private Saml2AuthenticatedPrincipal principal;

	// Mock SecurityContext
	@Mock
	private SecurityContext securityContext;

	@Before
	public void setup() {
		// Setup any initial configurations or mocks
	}

	@Test
	public void testValidSamlTokenRequest() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
//		when(myUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);

		// Mock JWT generation
		String jwtToken = "mockedJWTToken";
//		when(jwtTokenUtil.generateToken(any(UserDetails.class))).thenReturn(jwtToken);

		// Mock Authentication object and SecurityContext
		Saml2Authentication saml2Authentication = Mockito.mock(Saml2Authentication.class);
		when(saml2Authentication.isAuthenticated()).thenReturn(true);
		when(securityContext.getAuthentication()).thenReturn(saml2Authentication);
		SecurityContextHolder.setContext(securityContext);

		ResponseEntity<?> response = myController.samlToken(cookie);

		assertEquals(HttpStatus.OK.value(), response.getStatusCodeValue());
		// Add more assertions based on your response structure
	}

	@Test
	public void testInvalidSamlTokenRequest() {
		// Mock Cookie header
		String cookie = "otherCookie=xyz"; // No JSESSIONID in the cookie

		ResponseEntity<?> response = myController.samlToken(cookie);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCodeValue());
	}

	@Test
	public void testErrorGeneratingSamlToken() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
//		when(myUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);

		// Mock error in JWT token generation
//		when(jwtTokenUtil.generateToken(userDetails)).thenThrow(new RuntimeException("Token generation error"));

		// Mock an unauthenticated Saml2Authentication
		Saml2Authentication saml2Authentication = Mockito.mock(Saml2Authentication.class);
		when(saml2Authentication.isAuthenticated()).thenReturn(false);
		when(securityContext.getAuthentication()).thenReturn(saml2Authentication);
		SecurityContextHolder.setContext(securityContext);

		ResponseEntity<?> response = myController.samlToken(cookie);

		assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatusCodeValue());
	}
}
