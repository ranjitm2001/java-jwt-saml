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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
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

	@Before
	public void setup() {
		// Setup any initial configurations or mocks
	}

	@Test
	public void testValidSamlTokenRequest() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock principal
		when(principal.getName()).thenReturn("testUser");

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
		when(myUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);

		// Mock JWT generation
		String jwtToken = "mockedJWTToken";
		when(jwtTokenUtil.generateToken(any(UserDetails.class))).thenReturn(jwtToken);

		ResponseEntity<?> response = myController.samlToken(cookie, principal);

		assertEquals(200, response.getStatusCodeValue());
		// Add more assertions based on your response structure
	}

	@Test
	public void testInvalidSamlTokenRequest() {
		// Mock Cookie header
		String cookie = "otherCookie=xyz"; // No JSESSIONID in the cookie

		ResponseEntity<?> response = myController.samlToken(cookie, principal);
		assertEquals(400, response.getStatusCodeValue());
	}

	@Test
	public void testErrorGeneratingSamlToken() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock principal
		when(principal.getName()).thenReturn("testUser");

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
		when(myUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);

		// Mock error in JWT token generation
		when(jwtTokenUtil.generateToken(userDetails)).thenThrow(new RuntimeException("Token generation error"));

		ResponseEntity<?> response = myController.samlToken(cookie, principal);

		assertEquals(500, response.getStatusCodeValue());
	}
}

