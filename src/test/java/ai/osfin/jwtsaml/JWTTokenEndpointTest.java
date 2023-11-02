package ai.osfin.jwtsaml;

import ai.osfin.jwtsaml.controller.MyController;
import ai.osfin.jwtsaml.dto.AuthenticationRequest;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JWTTokenEndpointTest {

	@InjectMocks
	private MyController myController;

	@Mock
	private MyUserDetailsService myUserDetailsService;

	@Mock
	private JwtUtil jwtTokenUtil;

	@Mock
	private AuthenticationManager authenticationManager;

	@Before
	public void setup() {
		// Any setup needed
	}

	@Test
	public void testValidTokenCreation() throws Exception {
		// Mock AuthenticationRequest object
		AuthenticationRequest request = new AuthenticationRequest("username", "password");

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
		when(myUserDetailsService.loadUserByUsername("username")).thenReturn(userDetails);

		// Mock JWT generation
		String jwtToken = "mockedJWTToken";
		when(jwtTokenUtil.generateToken(userDetails)).thenReturn(jwtToken);

		ResponseEntity<?> response = myController.createJWTToken(request);

		assertEquals(HttpStatus.OK, response.getStatusCode());
	}


	@Test
	public void testInvalidTokenCreation() throws Exception {
		// Mock AuthenticationRequest object with invalid credentials
		AuthenticationRequest request = new AuthenticationRequest("invalidUser", "invalidPassword");

		// Mock behavior for loadUserByUsername returning null for invalid credentials
		when(myUserDetailsService.loadUserByUsername("invalidUser")).thenReturn(null);

		try {
			myController.createJWTToken(request);
		} catch (UsernameNotFoundException e) {
			assertEquals("User not found", e.getMessage());
		}
	}

	@Test
	public void testErrorGeneratingToken() {
		// Mock AuthenticationRequest object
		AuthenticationRequest request = new AuthenticationRequest("username", "password");

		// Mock behavior for loadUserByUsername
		UserDetails userDetails = Mockito.mock(UserDetails.class);
		when(myUserDetailsService.loadUserByUsername("username")).thenReturn(userDetails);

		// Mock error in JWT token generation
		when(jwtTokenUtil.generateToken(userDetails)).thenThrow(new RuntimeException("Token generation error"));

		Exception exception = assertThrows(Exception.class, () -> myController.createJWTToken(request));
		assertEquals("Error generating JWT token", exception.getMessage());
	}
}
