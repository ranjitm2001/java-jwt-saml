package ai.osfin.jwtsaml.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ai.osfin.jwtsaml.dto.AuthenticationRequest;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import ai.osfin.jwtsaml.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		if (authentication instanceof Saml2Authentication saml2Authentication && authentication.isAuthenticated()) {
			// Access the username from the authentication object
			String username = saml2Authentication.getName();
			AuthenticationRequest authenticationRequest = new AuthenticationRequest();
			authenticationRequest.setUsername(username);

			UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());

			// Update the JWT to include the SAML response token
			String jwt = jwtTokenUtil.generateToken(userDetails);

			// Update the success URL with the token
			String successUrl = "http://localhost:3000/login/saml-token?&token=" + jwt;
			setDefaultTargetUrl(successUrl);
		}
		super.onAuthenticationSuccess(request, response, authentication);
	}
}
