package ai.osfin.jwtsaml.controller;

import ai.osfin.jwtsaml.dto.AuthenticationRequest;
import ai.osfin.jwtsaml.dto.AuthenticationResponse;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import ai.osfin.jwtsaml.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class MyController {

	@GetMapping("/")
	public ResponseEntity<?> home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {

//		boolean jsessionid = cookie != null && cookie.contains("JSESSIONID");
//		if (!jsessionid) {
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("JSESSIONID is not present");
//		}

		// Check if Saml2AuthenticatedPrincipal is null
		if (principal == null || principal.getName() == null) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("SAML principal is null or doesn't contain a name");
		}

		AuthenticationRequest request = new AuthenticationRequest();
		request.setUsername(principal.getName()); // Assuming principal.getName() provides the username

		try {
			final UserDetails userDetails = myUserDetailsService
				.loadUserByUsername(request.getUsername());

			// Generate JWT token
			final String jwt = jwtTokenUtil.generateToken(userDetails);
			return ResponseEntity.ok(new AuthenticationResponse(jwt));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error generating JWT token");
		}
	}

	@GetMapping("/public/hello")
	public String helloPublic() {
		return "Public, Open, Free";
	}

	@GetMapping("/private/hello")
	public String hello() {
		return "Private resource: Hello World!";
	}

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@PostMapping("/authenticate")
	public ResponseEntity<?> createJWTToken(@RequestBody AuthenticationRequest request) throws Exception {
		// Validate the username and password | Request vs UserDetailsService
		try {
			authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
			);
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrect username or password", e);
		}
		// Fetch the complete user details from the database
		final UserDetails userDetails = myUserDetailsService
			.loadUserByUsername(request.getUsername());

		// Generate JWT token
		final String jwt = jwtTokenUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
}