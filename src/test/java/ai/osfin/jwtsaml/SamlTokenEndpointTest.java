package ai.osfin.jwtsaml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import static org.junit.Assert.assertEquals;
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
	private SecurityContext securityContext;

	@Mock
	private Saml2Authentication saml2Authentication;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpSession session;

	@Before
	public void setup() {
		// Setup any initial configurations or mocks
	}

	@Test
	public void testValidSamlTokenRequest() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock UserDetails and JWT generation
		UserDetails userDetails = Mockito.mock(UserDetails.class);
		when(myUserDetailsService.loadUserByUsername("testUser")).thenReturn(userDetails);

		String jwtToken = "mockedJWTToken";
		when(jwtTokenUtil.generateToken(userDetails)).thenReturn(jwtToken);

		// Mock behavior for Saml2Authentication
		when(saml2Authentication.isAuthenticated()).thenReturn(true);
		when(saml2Authentication.getName()).thenReturn("testUser");
		SecurityContextHolder.getContext().setAuthentication(saml2Authentication);

		// Mock HttpServletRequest and its getSession method
		HttpSession session = Mockito.mock(HttpSession.class);
		when(request.getSession()).thenReturn(session);

		ResponseEntity<?> response = myController.samlToken(request, cookie);

		assertEquals(HttpStatus.OK.value(), response.getStatusCodeValue());
	}


	@Test
	public void testInvalidSamlTokenRequest() {
		// Mock Cookie header without JSESSIONID
		String cookie = "otherCookie=xyz";

		ResponseEntity<?> response = myController.samlToken(request, cookie);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCodeValue());
	}

	@Test
	public void testErrorGeneratingSamlToken() {
		// Mock Cookie header
		String cookie = "JSESSIONID=someSessionId; otherCookie=xyz";

		// Mock UserDetails and error in JWT token generation
		UserDetails userDetails = Mockito.mock(UserDetails.class);

		// Mock an unauthenticated Saml2Authentication
		when(saml2Authentication.isAuthenticated()).thenReturn(false);
		SecurityContextHolder.getContext().setAuthentication(saml2Authentication);

		ResponseEntity<?> response = myController.samlToken(request, cookie);

		assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatusCodeValue());
	}
}
