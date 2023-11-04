package ai.osfin.jwtsaml.dto;


import lombok.Getter;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

@Getter
public class JwtSamlAuthenticationResponse {
	private String jwt;
	private Saml2Authentication saml2Authentication;

	public JwtSamlAuthenticationResponse(String jwt, Saml2Authentication saml2Authentication) {
		this.jwt = jwt;
		this.saml2Authentication = saml2Authentication;
	}

	public JwtSamlAuthenticationResponse() {
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	public void setSaml2Authentication(Saml2Authentication saml2Authentication) {
		this.saml2Authentication = saml2Authentication;
	}
}
