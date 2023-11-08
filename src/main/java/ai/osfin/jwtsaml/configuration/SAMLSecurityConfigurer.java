package ai.osfin.jwtsaml.configuration;

import ai.osfin.jwtsaml.filters.JwtRequestFilter;
import ai.osfin.jwtsaml.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

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

	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		// Create and configure your custom authentication entry point
		BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
		entryPoint.setRealmName("Custom Realm Name"); // Set your custom realm name
		// Set any other necessary configurations
		return entryPoint;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.cors();

		http
			.csrf().disable();

		http.authorizeRequests()
			.antMatchers("/", "/public/**", "/login/token").permitAll()
			.antMatchers("/private/**").authenticated();

		http
			.exceptionHandling()
			.authenticationEntryPoint(authenticationEntryPoint());

		http
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http
			.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}
}