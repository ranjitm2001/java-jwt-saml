package ai.osfin.jwtsaml.provider;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomSamlAuthenticationProvider implements AuthenticationProvider {

	private final OpenSaml4AuthenticationProvider authenticationProvider;

	public CustomSamlAuthenticationProvider() {
		this.authenticationProvider = new OpenSaml4AuthenticationProvider();
		this.authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// Implement authentication logic here if needed
		return authenticationProvider.authenticate(authentication);
	}

	private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {
		return (responseToken) -> {
			Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
				OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

			Saml2Authentication authentication = delegate.convert(responseToken);
			assert authentication != null;

			Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
			List<String> groups = principal.getAttribute("groups");

			Set<GrantedAuthority> authorities = new HashSet<>(authentication.getAuthorities());

			if (groups != null) {
				Set<GrantedAuthority> groupAuthorities = groups.stream()
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
				authorities.addAll(groupAuthorities);
			}

			return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
		};
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// Implement support logic here if needed
		return authenticationProvider.supports(authentication);
	}
}
