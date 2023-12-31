package ai.osfin.jwtsaml.controller;

import javax.servlet.http.HttpServletRequest;

import ai.osfin.jwtsaml.dto.AuthenticationRequest;
import ai.osfin.jwtsaml.dto.AuthenticationResponse;
import ai.osfin.jwtsaml.dto.JwtSamlAuthenticationResponse;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import ai.osfin.jwtsaml.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class MyController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@GetMapping("/")
	public Saml2AuthenticatedPrincipal home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
		return principal;
	}

	@GetMapping("/login/saml-token")
	public ResponseEntity<?> samlToken(HttpServletRequest request, @RequestHeader(value = "Cookie", required = false) String cookie) {
		boolean jSessionIdPresent = cookie != null && cookie.contains("JSESSIONID");
		if (!jSessionIdPresent) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("JSESSIONID is not present");
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (!(authentication instanceof Saml2Authentication saml2Authentication) || !authentication.isAuthenticated()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("SAML unauthenticated user");
		}

		// Clear the Session so that it remains stateless, from the next request
		request.getSession().invalidate();

		String username = saml2Authentication.getName();
		AuthenticationRequest authenticationRequest = new AuthenticationRequest();
		authenticationRequest.setUsername(username);

		try {
			final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());

			// Update the JWT to include the SAML response token
			final String jwt = jwtTokenUtil.generateToken(userDetails);

			// Create the response object to return
			JwtSamlAuthenticationResponse response = new JwtSamlAuthenticationResponse(jwt, saml2Authentication);

			return ResponseEntity.ok(response);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error generating tokens");
		}
	}

	@PostMapping("/login/token")
	public ResponseEntity<?> createJWTToken(@RequestBody AuthenticationRequest request) throws Exception {
		try {
			authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
			);
		} catch (BadCredentialsException e) {
			throw new BadCredentialsException("Incorrect username or password");
		}

		// Fetch the complete user details from the database
		final UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());

		if (userDetails == null) {
			throw new UsernameNotFoundException("User not found");
		}

		try {
			// Generate JWT token
			final String jwt = jwtTokenUtil.generateToken(userDetails);
			return ResponseEntity.ok(new AuthenticationResponse(jwt));
		} catch (Exception e) {
			throw new Exception("Error generating JWT token", e);
		}
	}

	@GetMapping("/public/hello")
	public ResponseEntity<String> helloPublic() {
		return ResponseEntity.ok("Public, Open, Free");
	}

	@GetMapping("/private/hello")
	public ResponseEntity<String> hello() {
		return ResponseEntity.ok("Private resource: Hello World!");
	}
}