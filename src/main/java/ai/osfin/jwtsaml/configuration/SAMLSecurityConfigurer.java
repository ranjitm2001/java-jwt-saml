package ai.osfin.jwtsaml.configuration;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import ai.osfin.jwtsaml.filters.JwtRequestFilter;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SAMLSecurityConfigurer extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtRequestFilter jwtRequestFilter;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable();

		http.authorizeRequests()
			.antMatchers("/", "/public/**", "/login/**").permitAll()
			.antMatchers("/private/**").authenticated();

		http
			.saml2Login(withDefaults())
			.saml2Logout(withDefaults());

		http
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

		http
			.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

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