package ai.osfin.jwtsaml.configuration;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import ai.osfin.jwtsaml.handler.CustomAuthenticationFailureHandler;
import ai.osfin.jwtsaml.handler.CustomAuthenticationSuccessHandler;
import ai.osfin.jwtsaml.provider.CustomSamlAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@Order(99)
public class SAMLConfigurer extends WebSecurityConfigurerAdapter {
	@Autowired
	private CustomSamlAuthenticationProvider samlAuthenticationProvider;

	@Autowired
	private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

	@Autowired
	private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.cors();

		http
			.requestMatchers()
			.antMatchers( "/saml2/authenticate/okta", "/login/saml2/sso/okta");

		http
			.saml2Login(saml2 -> saml2
				.successHandler(customAuthenticationSuccessHandler)
				.failureHandler(customAuthenticationFailureHandler)
				.authenticationManager(new ProviderManager(samlAuthenticationProvider))
			)
			.saml2Logout(withDefaults());
	}

	@Bean
	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(
		RelyingPartyRegistrationRepository registrations) {
		return new DefaultRelyingPartyRegistrationResolver((id) -> registrations.findByRegistrationId("okta"));
	}

	@Bean
	Saml2AuthenticationTokenConverter authentication(RelyingPartyRegistrationResolver registrations) {
		return new Saml2AuthenticationTokenConverter(registrations);
	}


	@Bean
	FilterRegistrationBean<Saml2MetadataFilter> metadata(RelyingPartyRegistrationResolver registrations) {
		Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
		FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
		filter.setOrder(-101);
		return filter;
	}

	@Bean
	RelyingPartyRegistrationRepository repository(
		@Value("classpath:credentials/local-saml.key") RSAPrivateKey privateKey) {
		RelyingPartyRegistration osfin = RelyingPartyRegistrations
			.fromMetadataLocation("https://dev-21824939.okta.com/app/exkcpw27nlbsux0BB5d7/sso/saml/metadata")
			.registrationId("okta")
			.signingX509Credentials(
				(c) -> c.add(Saml2X509Credential.signing(privateKey, relyingPartyCertificate())))
			.singleLogoutServiceLocation(
				"https://dev-21824939.okta.com/app/dev-21824939_localsimpleapp_1/exkcpw27nlbsux0BB5d7/slo/saml")
			.singleLogoutServiceResponseLocation("http://localhost:8080/logout/saml2/slo")
			.singleLogoutServiceBinding(Saml2MessageBinding.POST)
			.build();
		return new InMemoryRelyingPartyRegistrationRepository(osfin);
	}

	X509Certificate relyingPartyCertificate() {
		Resource resource = new ClassPathResource("credentials/local-saml.crt");
		try (InputStream is = resource.getInputStream()) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
		}
		catch (Exception ex) {
			throw new UnsupportedOperationException(ex);
		}
	}
}
