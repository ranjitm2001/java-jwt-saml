package ai.osfin.jwtsaml.controller;

import ai.osfin.jwtsaml.dto.AuthenticationRequest;
import ai.osfin.jwtsaml.dto.AuthenticationResponse;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import ai.osfin.jwtsaml.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class MyController {

	@GetMapping("/")
	public String openEndpoint() {
		return "Public call";
	}

	@GetMapping("/private/hello")
	public String hello() {
		return "Hello World!";
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
